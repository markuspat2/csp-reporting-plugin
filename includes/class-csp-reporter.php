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
     * @var CSP_Logger
     */
    private $logger;

    /**
     * Constructor
     *
     * @param CSP_Logger|null $logger
     */
    public function __construct($logger = null) {
        $this->logger = $logger instanceof CSP_Logger ? $logger : new CSP_Logger();
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
     * Process a validated CSP violation report.
     *
     * @param array $report_data
     */
    public function process_report($report_data) {
        $enriched_report = $this->enrich_report_data($report_data);

        $log_success = $this->logger->log_violation($enriched_report);

        if (!$log_success) {
            error_log('CSP Reporting Plugin: Failed to log violation report');
        }

        $this->check_admin_notifications($enriched_report);
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
     * Get violation statistics
     *
     * @param int $days
     * @return array
     */
    public function get_violation_statistics($days = 7) {
        $log_files = $this->logger->get_log_files();
        $cutoff_time = time() - ($days * 24 * 60 * 60);
        $stats = array(
            'total_violations' => 0,
            'by_severity' => array('low' => 0, 'medium' => 0, 'high' => 0),
            'by_directive' => array(),
            'by_uri' => array(),
            'recent_violations' => array(),
        );

        foreach ($log_files as $file) {
            if (filemtime($file) < $cutoff_time) {
                continue;
            }

            foreach ($this->logger->read_log_entries($file) as $log_data) {
                if (!isset($log_data['report_data']['csp-report'])) {
                    continue;
                }

                $report_data = $log_data['report_data'];
                $csp_report = $report_data['csp-report'];

                $stats['total_violations']++;

                $severity = isset($report_data['severity']) ? $report_data['severity'] : 'low';
                if (isset($stats['by_severity'][$severity])) {
                    $stats['by_severity'][$severity]++;
                }

                $directive = $csp_report['violated-directive'];
                $stats['by_directive'][$directive] = ($stats['by_directive'][$directive] ?? 0) + 1;

                $blocked_uri = isset($csp_report['blocked-uri']) ? $csp_report['blocked-uri'] : '';
                $stats['by_uri'][$blocked_uri] = ($stats['by_uri'][$blocked_uri] ?? 0) + 1;

                if (count($stats['recent_violations']) < 10) {
                    $stats['recent_violations'][] = array(
                        'timestamp' => isset($log_data['timestamp']) ? $log_data['timestamp'] : '',
                        'severity' => $severity,
                        'directive' => $directive,
                        'blocked_uri' => $blocked_uri,
                        'document_uri' => $csp_report['document-uri'],
                    );
                }
            }
        }

        arsort($stats['by_directive']);
        arsort($stats['by_uri']);

        return $stats;
    }
}
