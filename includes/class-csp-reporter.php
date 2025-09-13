<?php
/**
 * CSP Reporter Class
 * 
 * Handles CSP violation report processing and logging
 */

if (!defined('ABSPATH')) {
    exit;
}

class CSP_Reporter {
    
    private $logger;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->logger = new CSP_Logger();
    }
    
    /**
     * Handle CSP violation report
     */
    public function handle_report() {
        // Get the raw input
        $input = file_get_contents('php://input');
        
        if (empty($input)) {
            $this->send_error_response('No data received', 400);
            return;
        }
        
        // Parse JSON data
        $report_data = json_decode($input, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->send_error_response('Invalid JSON data: ' . json_last_error_msg(), 400);
            return;
        }
        
        // Validate report structure
        if (!$this->validate_report_structure($report_data)) {
            $this->send_error_response('Invalid report structure', 400);
            return;
        }
        
        // Process the report
        $this->process_report($report_data);
        
        // Send success response
        $this->send_success_response();
    }
    
    /**
     * Validate CSP report structure
     * 
     * @param array $report_data
     * @return bool
     */
    private function validate_report_structure($report_data) {
        if (!is_array($report_data)) {
            return false;
        }
        
        // Check for required top-level fields
        if (!isset($report_data['csp-report'])) {
            return false;
        }
        
        $csp_report = $report_data['csp-report'];
        
        // Check for required CSP report fields
        $required_fields = array(
            'document-uri',
            'violated-directive',
            'effective-directive',
            'original-policy',
            'disposition',
            'blocked-uri',
            'status-code'
        );
        
        foreach ($required_fields as $field) {
            if (!isset($csp_report[$field])) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Process CSP violation report
     * 
     * @param array $report_data
     */
    private function process_report($report_data) {
        // Add additional metadata
        $enriched_report = $this->enrich_report_data($report_data);
        
        // Log the violation
        $log_success = $this->logger->log_violation($enriched_report);
        
        if (!$log_success) {
            error_log('CSP Reporting Plugin: Failed to log violation report');
        }
        
        // Check if we should trigger admin notifications
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
        
        // Add server information
        $enriched['server_info'] = array(
            'timestamp' => current_time('mysql'),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown',
            'referer' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
            'request_method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'Unknown',
            'content_type' => isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '',
            'content_length' => isset($_SERVER['CONTENT_LENGTH']) ? intval($_SERVER['CONTENT_LENGTH']) : 0
        );
        
        // Add client IP
        $enriched['client_ip'] = $this->get_client_ip();
        
        // Add WordPress context if available
        if (function_exists('get_current_user_id')) {
            $enriched['wp_context'] = array(
                'user_id' => get_current_user_id(),
                'is_admin' => is_admin(),
                'is_ajax' => wp_doing_ajax(),
                'is_cron' => wp_doing_cron(),
                'is_rest' => defined('REST_REQUEST') && REST_REQUEST
            );
        }
        
        // Add severity assessment
        $enriched['severity'] = $this->assess_violation_severity($report_data['csp-report']);
        
        return $enriched;
    }
    
    /**
     * Assess violation severity
     * 
     * @param array $csp_report
     * @return string
     */
    private function assess_violation_severity($csp_report) {
        $severity = 'low';
        
        // Check for high-severity violations
        $high_severity_patterns = array(
            'script-src' => array('unsafe-eval', 'unsafe-inline'),
            'object-src' => array('*', 'data:', 'blob:'),
            'base-uri' => array('*', 'data:', 'javascript:'),
            'form-action' => array('*', 'javascript:')
        );
        
        $violated_directive = $csp_report['violated-directive'];
        $blocked_uri = $csp_report['blocked-uri'];
        
        // Check for script injection attempts
        if (strpos($violated_directive, 'script-src') !== false) {
            if (strpos($blocked_uri, 'javascript:') !== false || 
                strpos($blocked_uri, 'data:') !== false ||
                strpos($blocked_uri, 'vbscript:') !== false) {
                $severity = 'high';
            } elseif (strpos($blocked_uri, 'unsafe-inline') !== false || 
                     strpos($blocked_uri, 'unsafe-eval') !== false) {
                $severity = 'medium';
            }
        }
        
        // Check for object/embed violations
        if (strpos($violated_directive, 'object-src') !== false) {
            $severity = 'high';
        }
        
        // Check for base-uri violations
        if (strpos($violated_directive, 'base-uri') !== false) {
            $severity = 'high';
        }
        
        // Check for form-action violations
        if (strpos($violated_directive, 'form-action') !== false) {
            $severity = 'high';
        }
        
        return $severity;
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
        
        $severity = $report_data['severity'];
        $csp_report = $report_data['csp-report'];
        
        // Only notify for medium and high severity violations
        if (in_array($severity, array('medium', 'high'))) {
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
            __('CSP Violation Alert: %s violation detected on %s. Blocked URI: %s', 'csp-reporting'),
            strtoupper($severity),
            $csp_report['document-uri'],
            $csp_report['blocked-uri']
        );
        
        // Log to WordPress error log
        error_log('CSP Reporting Plugin: ' . $message);
        
        // Store notification for admin dashboard
        $notifications = get_option('csp_admin_notifications', array());
        $notifications[] = array(
            'timestamp' => current_time('mysql'),
            'severity' => $severity,
            'message' => $message,
            'report_data' => $report_data
        );
        
        // Keep only last 50 notifications
        if (count($notifications) > 50) {
            $notifications = array_slice($notifications, -50);
        }
        
        update_option('csp_admin_notifications', $notifications);
    }
    
    /**
     * Get client IP address
     * 
     * @return string
     */
    private function get_client_ip() {
        $ip_keys = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        );
        
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                $ip = $_SERVER[$key];
                if (strpos($ip, ',') !== false) {
                    $ip = explode(',', $ip)[0];
                }
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'Unknown';
    }
    
    /**
     * Send success response
     */
    private function send_success_response() {
        http_response_code(204);
        exit;
    }
    
    /**
     * Send error response
     * 
     * @param string $message
     * @param int $code
     */
    private function send_error_response($message, $code = 400) {
        http_response_code($code);
        header('Content-Type: application/json');
        echo json_encode(array(
            'error' => $message,
            'code' => $code
        ));
        exit;
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
            'recent_violations' => array()
        );
        
        foreach ($log_files as $file) {
            if (filemtime($file) < $cutoff_time) {
                continue;
            }
            
            $content = file_get_contents($file);
            if (!$content) {
                continue;
            }
            
            // Parse log entries
            $entries = explode(str_repeat('-', 80), $content);
            
            foreach ($entries as $entry) {
                if (empty(trim($entry))) {
                    continue;
                }
                
                $log_data = json_decode(trim($entry), true);
                if (!$log_data || !isset($log_data['report_data'])) {
                    continue;
                }
                
                $report_data = $log_data['report_data'];
                $csp_report = $report_data['csp-report'];
                
                $stats['total_violations']++;
                
                // Count by severity
                if (isset($report_data['severity'])) {
                    $stats['by_severity'][$report_data['severity']]++;
                }
                
                // Count by directive
                $directive = $csp_report['violated-directive'];
                if (!isset($stats['by_directive'][$directive])) {
                    $stats['by_directive'][$directive] = 0;
                }
                $stats['by_directive'][$directive]++;
                
                // Count by blocked URI
                $blocked_uri = $csp_report['blocked-uri'];
                if (!isset($stats['by_uri'][$blocked_uri])) {
                    $stats['by_uri'][$blocked_uri] = 0;
                }
                $stats['by_uri'][$blocked_uri]++;
                
                // Add to recent violations (last 10)
                if (count($stats['recent_violations']) < 10) {
                    $stats['recent_violations'][] = array(
                        'timestamp' => $log_data['timestamp'],
                        'severity' => $report_data['severity'] ?? 'unknown',
                        'directive' => $directive,
                        'blocked_uri' => $blocked_uri,
                        'document_uri' => $csp_report['document-uri']
                    );
                }
            }
        }
        
        // Sort by count
        arsort($stats['by_directive']);
        arsort($stats['by_uri']);
        
        return $stats;
    }
}

