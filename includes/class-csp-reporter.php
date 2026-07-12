<?php
/**
 * CSP Reporter Class
 *
 * Receives CSP violation reports on a REST endpoint, validates and enriches
 * them, and hands them to the logger.
 */

if (!defined('ABSPATH')) {
    exit;
}

class CSP_Reporter {

    /**
     * Reject report payloads larger than this many bytes.
     */
    const MAX_PAYLOAD_BYTES = 32768;

    /**
     * Default per-IP rate limit (reports per minute).
     */
    const RATE_LIMIT_PER_MINUTE = 30;

    /**
     * Default site-wide daily cap on accepted reports.
     */
    const RATE_LIMIT_PER_DAY = 5000;

    /**
     * @var CSP_Logger
     */
    private $logger;

    /**
     * @var CSP_Database
     */
    private $database;

    /**
     * Constructor
     *
     * @param CSP_Logger|null $logger
     * @param CSP_Database|null $database
     */
    public function __construct($logger = null, $database = null) {
        $this->logger = $logger instanceof CSP_Logger ? $logger : new CSP_Logger();
        $this->database = $database instanceof CSP_Database ? $database : new CSP_Database();
    }

    /**
     * Register the REST report endpoint.
     *
     * POST wp-json/csp-reporting/v1/report
     *
     * Browsers post violation reports here without authentication, so the
     * permission callback is open by design; payloads are size-checked and
     * validated instead.
     */
    public function register_routes() {
        register_rest_route('csp-reporting/v1', '/report', array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => array($this, 'handle_report'),
            'permission_callback' => '__return_true',
        ));
    }

    /**
     * Handle an incoming CSP violation report.
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public function handle_report($request) {
        $body = $request->get_body();

        if (empty($body)) {
            return $this->error_response('No data received', 400);
        }

        if (strlen($body) > self::MAX_PAYLOAD_BYTES) {
            return $this->error_response('Payload too large', 413);
        }

        if (!$this->check_rate_limit()) {
            return $this->error_response('Too many reports', 429);
        }

        // Browsers send Content-Type: application/csp-report, which the REST
        // API does not parse into params — decode the raw body ourselves.
        $report_data = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return $this->error_response('Invalid JSON data', 400);
        }

        if (!$this->validate_report_structure($report_data)) {
            return $this->error_response('Invalid report structure', 400);
        }

        $this->process_report($report_data);

        return new WP_REST_Response(null, 204);
    }

    /**
     * Validate CSP report structure.
     *
     * Only the fields every browser reliably sends are required; the rest of
     * the report-uri payload varies by engine and version.
     *
     * @param mixed $report_data
     * @return bool
     */
    public function validate_report_structure($report_data) {
        if (!is_array($report_data) || !isset($report_data['csp-report']) || !is_array($report_data['csp-report'])) {
            return false;
        }

        $csp_report = $report_data['csp-report'];

        $required_fields = array('document-uri', 'violated-directive');

        foreach ($required_fields as $field) {
            if (empty($csp_report[$field]) || !is_string($csp_report[$field])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Enforce the per-IP and site-wide report rate limits.
     *
     * The endpoint is unauthenticated by necessity, so this is the main
     * defense against disk/DB-fill floods.
     *
     * @return bool True when the request is within limits.
     */
    private function check_rate_limit() {
        $options = get_option('csp_reporting_options', array());

        /**
         * Filter the per-IP reports-per-minute limit. Return 0 to disable.
         *
         * @param int $limit
         */
        $per_minute = apply_filters(
            'csp_reporting_rate_limit_per_minute',
            isset($options['rate_limit_per_minute']) ? (int) $options['rate_limit_per_minute'] : self::RATE_LIMIT_PER_MINUTE
        );

        /**
         * Filter the site-wide reports-per-day cap. Return 0 to disable.
         *
         * @param int $limit
         */
        $per_day = apply_filters('csp_reporting_rate_limit_per_day', self::RATE_LIMIT_PER_DAY);

        if ($per_minute > 0) {
            $ip_key = 'csp_rl_' . md5(CSP_Utils::get_client_ip());
            $count = (int) get_transient($ip_key);

            if ($count >= $per_minute) {
                return false;
            }

            set_transient($ip_key, $count + 1, MINUTE_IN_SECONDS);
        }

        if ($per_day > 0) {
            $count = (int) get_transient('csp_rl_global');

            if ($count >= $per_day) {
                return false;
            }

            set_transient('csp_rl_global', $count + 1, DAY_IN_SECONDS);
        }

        return true;
    }

    /**
     * Process a validated CSP violation report.
     *
     * @param array $report_data
     * @return bool Whether the report was recorded (false when ignored).
     */
    public function process_report($report_data) {
        $csp_report = $report_data['csp-report'];

        // Drop known noise (browser extensions etc.) before it hits storage.
        if (CSP_Utils::matches_ignore_patterns($csp_report, CSP_Utils::get_ignore_patterns())) {
            return false;
        }

        $enriched_report = $this->enrich_report_data($report_data);

        /**
         * Filter the enriched report before it is stored.
         *
         * Return a falsy value to discard the report.
         *
         * @param array $enriched_report Report payload plus server_info,
         *                               client_ip, and severity keys.
         */
        $enriched_report = apply_filters('csp_report_data', $enriched_report);

        if (empty($enriched_report) || !isset($enriched_report['csp-report'])) {
            return false;
        }

        $csp_report = $enriched_report['csp-report'];

        $stored = $this->database->insert_violation(array(
            'severity' => $enriched_report['severity'],
            'directive' => $csp_report['violated-directive'],
            'blocked_uri' => isset($csp_report['blocked-uri']) ? $csp_report['blocked-uri'] : '',
            'document_uri' => $csp_report['document-uri'],
            'source_file' => isset($csp_report['source-file']) ? $csp_report['source-file'] : '',
            'line_number' => isset($csp_report['line-number']) ? (int) $csp_report['line-number'] : 0,
            'column_number' => isset($csp_report['column-number']) ? (int) $csp_report['column-number'] : 0,
            'disposition' => isset($csp_report['disposition']) ? $csp_report['disposition'] : 'report',
            'user_agent' => $enriched_report['server_info']['user_agent'],
            'client_ip' => $enriched_report['client_ip'],
        ));

        if (!$stored) {
            error_log('CSP Reporting Plugin: Failed to store violation report');
        }

        // Raw file log is optional since 2.0 (the database is authoritative).
        $options = get_option('csp_reporting_options', array());
        if (!empty($options['file_logging_enabled'])) {
            $this->logger->log_violation($enriched_report);
        }

        if ($stored) {
            /**
             * Fires after a violation report has been recorded.
             *
             * @param array $enriched_report The stored report payload.
             * @param string $severity low|medium|high.
             */
            do_action('csp_violation_logged', $enriched_report, $enriched_report['severity']);
        }

        $this->check_admin_notifications($enriched_report);

        return $stored;
    }

    /**
     * Enrich report data with additional information
     *
     * @param array $report_data
     * @return array
     */
    private function enrich_report_data($report_data) {
        $enriched = $report_data;

        $enriched['server_info'] = array(
            'timestamp' => current_time('mysql'),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown',
            'referer' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
            'content_type' => isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '',
        );

        $enriched['client_ip'] = CSP_Utils::get_client_ip();
        $enriched['severity'] = $this->assess_violation_severity($report_data['csp-report']);

        return $enriched;
    }

    /**
     * Assess violation severity.
     *
     * @param array $csp_report
     * @return string low|medium|high
     */
    public function assess_violation_severity($csp_report) {
        $violated_directive = isset($csp_report['violated-directive']) ? $csp_report['violated-directive'] : '';
        $blocked_uri = isset($csp_report['blocked-uri']) ? $csp_report['blocked-uri'] : '';

        // Directives whose violation always indicates a serious problem.
        $high_severity_directives = array('object-src', 'base-uri', 'form-action', 'frame-ancestors');

        foreach ($high_severity_directives as $directive) {
            if (strpos($violated_directive, $directive) === 0) {
                return 'high';
            }
        }

        if (strpos($violated_directive, 'script-src') === 0) {
            // Dangerous URI schemes are potential injection attempts.
            if (preg_match('#^(javascript|data|vbscript|blob):#i', $blocked_uri)) {
                return 'high';
            }

            // Browsers report blocked inline scripts / eval with these
            // keyword values (not the full 'unsafe-*' source expressions).
            if (in_array($blocked_uri, array('inline', 'eval', 'wasm-eval', ''), true)) {
                return 'medium';
            }

            return 'medium';
        }

        return 'low';
    }

    /**
     * Check if admin notifications should be triggered
     *
     * @param array $report_data
     */
    private function check_admin_notifications($report_data) {
        $options = get_option('csp_reporting_options', array());

        if (empty($options['enable_admin_notices'])) {
            return;
        }

        if (in_array($report_data['severity'], array('medium', 'high'), true)) {
            $this->trigger_admin_notification($report_data);
        }
    }

    /**
     * Trigger admin notification
     *
     * @param array $report_data
     */
    private function trigger_admin_notification($report_data) {
        $csp_report = $report_data['csp-report'];
        $severity = $report_data['severity'];

        $message = sprintf(
            __('CSP Violation Alert: %1$s violation detected on %2$s. Blocked URI: %3$s', 'csp-reporting'),
            strtoupper($severity),
            $csp_report['document-uri'],
            isset($csp_report['blocked-uri']) ? $csp_report['blocked-uri'] : ''
        );

        error_log('CSP Reporting Plugin: ' . $message);

        $notifications = get_option('csp_admin_notifications', array());
        $notifications[] = array(
            'timestamp' => current_time('mysql'),
            'severity' => $severity,
            'message' => $message,
        );

        // Keep only last 50 notifications
        if (count($notifications) > 50) {
            $notifications = array_slice($notifications, -50);
        }

        update_option('csp_admin_notifications', $notifications, false);
    }

    /**
     * Build a synthetic report for the admin "Send Test Report" action.
     *
     * @return array
     */
    public function create_test_report() {
        return array(
            'csp-report' => array(
                'document-uri' => home_url('/csp-test-page/'),
                'violated-directive' => "script-src 'self'",
                'effective-directive' => 'script-src',
                'original-policy' => "script-src 'self'; object-src 'none';",
                'disposition' => 'report',
                'blocked-uri' => 'https://example.com/test-script.js',
                'status-code' => 200,
                'source-file' => home_url('/csp-test-page/'),
                'line-number' => 1,
                'column-number' => 1,
            ),
        );
    }

    /**
     * Build an error response.
     *
     * @param string $message
     * @param int $code
     * @return WP_REST_Response
     */
    private function error_response($message, $code) {
        return new WP_REST_Response(array(
            'error' => $message,
            'code' => $code,
        ), $code);
    }

    /**
     * Get violation statistics for the last N days.
     *
     * @param int $days
     * @return array See CSP_Database::get_stats().
     */
    public function get_violation_statistics($days = 7) {
        return $this->database->get_stats($days);
    }
}
