<?php
/**
 * CSP Reporter Class
 *
 * Receives CSP violation reports on a REST endpoint, validates and enriches
 * them, and hands them to the logger.
 */

if ( ! defined('ABSPATH')) {
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
    public function __construct( $logger = null, $database = null ) {
        $this->logger   = $logger instanceof CSP_Logger ? $logger : new CSP_Logger();
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
            'callback' => array( $this, 'handle_report' ),
            'permission_callback' => '__return_true',
        ));
    }

    /**
     * Handle an incoming CSP violation report.
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public function handle_report( $request ) {
        $body = $request->get_body();

        if (empty($body)) {
            return $this->error_response('No data received', 400);
        }

        if (strlen($body) > self::MAX_PAYLOAD_BYTES) {
            return $this->error_response('Payload too large', 413);
        }

        // Browsers send Content-Type: application/csp-report (report-uri) or
        // application/reports+json (report-to), neither of which the REST
        // API parses into params — decode the raw body ourselves.
        $decoded = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return $this->error_response('Invalid JSON data', 400);
        }

        $reports = $this->extract_reports($decoded);

        if (empty($reports)) {
            return $this->error_response('Invalid report structure', 400);
        }

        // Limits count reports, not requests: one Reporting API batch can
        // carry a hundred-plus reports in the 32 KB payload cap.
        $granted = $this->consume_rate_limit(count($reports));

        if ($granted < 1) {
            return $this->error_response('Too many reports', 429);
        }

        foreach (array_slice($reports, 0, $granted) as $report_data) {
            $this->process_report($report_data);
        }

        return new WP_REST_Response(null, 204);
    }

    /**
     * Normalize a decoded payload into a list of legacy-shaped reports.
     *
     * Handles both formats:
     * - report-uri: a single {"csp-report": {...}} object.
     * - report-to (Reporting API): a batch array of report objects with
     *   camelCase bodies.
     *
     * @param mixed $decoded
     * @return array[] Zero or more {"csp-report": {...}} arrays.
     */
    public function extract_reports( $decoded ) {
        if ( ! is_array($decoded)) {
            return array();
        }

        // Legacy single report.
        if (isset($decoded['csp-report'])) {
            $decoded = self::normalize_report($decoded);
            return $this->validate_report_structure($decoded) ? array( $decoded ) : array();
        }

        // Reporting API batch.
        $reports = array();

        foreach ($decoded as $item) {
            if ( ! is_array($item) || ! isset($item['type'], $item['body']) || $item['type'] !== 'csp-violation' || ! is_array($item['body'])) {
                continue;
            }

            $body = $item['body'];

            $report = array(
                'csp-report' => array(
                    'document-uri' => isset($body['documentURL']) ? $body['documentURL'] : ( isset($item['url']) ? $item['url'] : '' ),
                    'violated-directive' => isset($body['effectiveDirective']) ? $body['effectiveDirective'] : '',
                    'effective-directive' => isset($body['effectiveDirective']) ? $body['effectiveDirective'] : '',
                    'original-policy' => isset($body['originalPolicy']) ? $body['originalPolicy'] : '',
                    'disposition' => isset($body['disposition']) ? $body['disposition'] : 'report',
                    'blocked-uri' => isset($body['blockedURL']) ? $body['blockedURL'] : '',
                    'status-code' => isset($body['statusCode']) ? (int) $body['statusCode'] : 0,
                    'source-file' => isset($body['sourceFile']) ? $body['sourceFile'] : '',
                    'line-number' => isset($body['lineNumber']) ? (int) $body['lineNumber'] : 0,
                    'column-number' => isset($body['columnNumber']) ? (int) $body['columnNumber'] : 0,
                    'script-sample' => isset($body['sample']) ? $body['sample'] : '',
                ),
            );

            $report = self::normalize_report($report);

            if ($this->validate_report_structure($report)) {
                $reports[] = $report;
            }
        }

        return $reports;
    }

    /**
     * Get the code sample from a legacy-shaped report.
     *
     * Browsers include the first 40 characters of blocked inline code (or
     * the eval'd string) when the directive has 'report-sample': as
     * script-sample in report-uri payloads, and as sample in Reporting API
     * bodies (which extract_reports() maps to script-sample).
     *
     * @param array $csp_report
     * @return string
     */
    public static function extract_sample( $csp_report ) {
        return CSP_Utils::sanitize_sample(isset($csp_report['script-sample']) ? $csp_report['script-sample'] : '');
    }

    /**
     * Coerce a report's fields to the types the rest of the pipeline expects.
     *
     * The endpoint is public, so any field can arrive as an array or object
     * (`"blocked-uri": ["x"]`), which used to reach preg_match()/substr() and
     * fatal with a TypeError. Text fields become strings (non-scalars are
     * dropped), numeric fields become ints, and unknown keys pass through.
     *
     * @param array $report_data {"csp-report": {...}}
     * @return array
     */
    public static function normalize_report( $report_data ) {
        if ( ! isset($report_data['csp-report']) || ! is_array($report_data['csp-report'])) {
            return $report_data;
        }

        $text_fields = array( 'document-uri', 'referrer', 'violated-directive', 'effective-directive', 'original-policy', 'disposition', 'blocked-uri', 'source-file', 'script-sample' );
        $int_fields  = array( 'status-code', 'line-number', 'column-number' );

        foreach ($report_data['csp-report'] as $key => $value) {
            if (in_array($key, $text_fields, true)) {
                if (is_scalar($value)) {
                    $report_data['csp-report'][$key] = (string) $value;
                } else {
                    unset($report_data['csp-report'][$key]);
                }
            } elseif (in_array($key, $int_fields, true)) {
                $report_data['csp-report'][$key] = is_numeric($value) ? max(0, (int) $value) : 0;
            }
        }

        return $report_data;
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
    public function validate_report_structure( $report_data ) {
        if ( ! is_array($report_data) || ! isset($report_data['csp-report']) || ! is_array($report_data['csp-report'])) {
            return false;
        }

        $csp_report = $report_data['csp-report'];

        $required_fields = array( 'document-uri', 'violated-directive' );

        foreach ($required_fields as $field) {
            if (empty($csp_report[$field]) || ! is_string($csp_report[$field])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Take up to $wanted reports from the per-IP and site-wide allowances.
     *
     * The endpoint is unauthenticated by necessity, so this is the main
     * defense against disk/DB-fill floods.
     *
     * Each limit is a fixed window keyed by the current minute (per IP) or
     * UTC day (site-wide). Re-setting one rolling transient on every report,
     * as before, pushed its expiry forward each time, so the "per day" cap
     * never reset while reports kept arriving and became a cumulative cap.
     *
     * @param int $wanted Reports in this request.
     * @return int Reports that may be processed (0..$wanted).
     */
    private function consume_rate_limit( $wanted ) {
        $options = get_option('csp_reporting_options', array());

        /**
         * Filter the per-IP reports-per-minute limit. Return 0 to disable.
         *
         * @param int $limit
         */
        $per_minute = (int) apply_filters(
            'csp_reporting_rate_limit_per_minute',
            isset($options['rate_limit_per_minute']) ? (int) $options['rate_limit_per_minute'] : self::RATE_LIMIT_PER_MINUTE
        );

        /**
         * Filter the site-wide reports-per-day cap. Return 0 to disable.
         *
         * @param int $limit
         */
        $per_day = (int) apply_filters('csp_reporting_rate_limit_per_day', self::RATE_LIMIT_PER_DAY);

        $now     = time();
        $windows = array();

        if ($per_minute > 0) {
            $windows[] = array( 'csp_rl_' . md5(CSP_Utils::get_client_ip()) . '_' . (int) floor($now / MINUTE_IN_SECONDS), $per_minute, 2 * MINUTE_IN_SECONDS );
        }

        if ($per_day > 0) {
            $windows[] = array( 'csp_rl_global_' . gmdate('Ymd', $now), $per_day, 2 * DAY_IN_SECONDS );
        }

        $granted = max(0, (int) $wanted);

        foreach ($windows as $window) {
            $granted = min($granted, max(0, $window[1] - (int) get_transient($window[0])));
        }

        if ($granted > 0) {
            foreach ($windows as $window) {
                set_transient($window[0], (int) get_transient($window[0]) + $granted, $window[2]);
            }
        }

        return $granted;
    }

    /**
     * Process a validated CSP violation report.
     *
     * @param array $report_data
     * @return bool Whether the report was recorded (false when ignored).
     */
    public function process_report( $report_data ) {
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

        if (empty($enriched_report) || ! isset($enriched_report['csp-report'])) {
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
            'script_sample' => self::extract_sample($csp_report),
            'disposition' => isset($csp_report['disposition']) ? $csp_report['disposition'] : 'report',
            'user_agent' => $enriched_report['server_info']['user_agent'],
            'client_ip' => $enriched_report['client_ip'],
        ));

        if ( ! $stored) {
            error_log('CSP Reporting Plugin: Failed to store violation report');
        }

        // Raw file log is optional since 2.0 (the database is authoritative).
        $options = get_option('csp_reporting_options', array());
        if ( ! empty($options['file_logging_enabled'])) {
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

        return $stored;
    }

    /**
     * Enrich report data with additional information
     *
     * @param array $report_data
     * @return array
     */
    private function enrich_report_data( $report_data ) {
        $enriched = $report_data;

        $enriched['server_info'] = array(
            'timestamp' => current_time('mysql'),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown',
            'referer' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
            'content_type' => isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '',
        );

        // IPs are personal data; only record them when explicitly enabled.
        // Rate limiting still works either way — it hashes the IP into a
        // transient key and never persists it.
        $options = get_option('csp_reporting_options', array());

        $enriched['client_ip'] = ! empty($options['store_client_ip']) ? CSP_Utils::get_client_ip() : '';
        $enriched['severity']  = $this->assess_violation_severity($report_data['csp-report']);

        return $enriched;
    }

    /**
     * Assess violation severity.
     *
     * @param array $csp_report
     * @return string low|medium|high
     */
    public function assess_violation_severity( $csp_report ) {
        $violated_directive = isset($csp_report['violated-directive']) ? $csp_report['violated-directive'] : '';
        $blocked_uri        = isset($csp_report['blocked-uri']) ? $csp_report['blocked-uri'] : '';

        // Directives whose violation always indicates a serious problem.
        $high_severity_directives = array( 'object-src', 'base-uri', 'form-action', 'frame-ancestors' );

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

            // Everything else on script-src — external hosts and inline/eval
            // (reported as 'inline'/'eval', not 'unsafe-*') — needs review.
            return 'medium';
        }

        return 'low';
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
    private function error_response( $message, $code ) {
        return new WP_REST_Response(array(
            'error' => $message,
            'code' => $code,
        ), $code);
    }
}
