<?php
/**
 * CSP Logger Class
 * 
 * Handles logging of CSP violation reports to files
 */

if (!defined('ABSPATH')) {
    exit;
}

class CSP_Logger {
    
    private $log_dir;
    private $max_file_size;
    private $current_log_file;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->log_dir = CSP_REPORTING_LOG_DIR;
        $options = get_option('csp_reporting_options', array());
        $this->max_file_size = !empty($options['log_max_size']) ? intval($options['log_max_size']) : 10485760; // 10MB default
    }
    
    /**
     * Log CSP violation report
     * 
     * @param array $report_data The CSP violation report data
     * @return bool True on success, false on failure
     */
    public function log_violation($report_data) {
        if (!$this->is_valid_report($report_data)) {
            return false;
        }
        
        $log_entry = $this->format_log_entry($report_data);
        $log_file = $this->get_current_log_file();
        
        if (!$log_file) {
            return false;
        }
        
        // Check if we need to rotate the log file
        if ($this->should_rotate_log($log_file)) {
            $this->rotate_log_file();
            $log_file = $this->get_current_log_file();
        }
        
        // Write to log file
        $result = file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
        
        if ($result === false) {
            error_log('CSP Reporting Plugin: Failed to write to log file');
            return false;
        }
        
        return true;
    }
    
    /**
     * Validate CSP report data
     * 
     * @param array $report_data
     * @return bool
     */
    private function is_valid_report($report_data) {
        if (!is_array($report_data)) {
            return false;
        }
        
        // Check for required fields
        $required_fields = array('csp-report');
        foreach ($required_fields as $field) {
            if (!isset($report_data[$field])) {
                return false;
            }
        }
        
        // Validate the CSP report structure
        $csp_report = $report_data['csp-report'];
        if (!isset($csp_report['document-uri']) || !isset($csp_report['violated-directive'])) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Format log entry
     * 
     * @param array $report_data
     * @return string
     */
    private function format_log_entry($report_data) {
        $timestamp = current_time('Y-m-d H:i:s');
        $ip_address = $this->get_client_ip();
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown';
        
        $log_entry = array(
            'timestamp' => $timestamp,
            'ip_address' => $ip_address,
            'user_agent' => $user_agent,
            'report_data' => $report_data
        );
        
        return json_encode($log_entry, JSON_PRETTY_PRINT) . "\n" . str_repeat('-', 80) . "\n";
    }
    
    /**
     * Get current log file path
     * 
     * @return string|false
     */
    private function get_current_log_file() {
        if ($this->current_log_file && file_exists($this->current_log_file)) {
            return $this->current_log_file;
        }
        
        $date = current_time('Y-m-d');
        $log_file = $this->log_dir . 'csp-reports-' . $date . '.log';
        
        // Ensure directory exists
        if (!file_exists($this->log_dir)) {
            if (!wp_mkdir_p($this->log_dir)) {
                error_log('CSP Reporting Plugin: Failed to create log directory');
                return false;
            }
        }
        
        $this->current_log_file = $log_file;
        return $log_file;
    }
    
    /**
     * Check if log file should be rotated
     * 
     * @param string $log_file
     * @return bool
     */
    private function should_rotate_log($log_file) {
        if (!file_exists($log_file)) {
            return false;
        }
        
        return filesize($log_file) >= $this->max_file_size;
    }
    
    /**
     * Rotate log file
     */
    private function rotate_log_file() {
        if (!$this->current_log_file || !file_exists($this->current_log_file)) {
            return;
        }
        
        $timestamp = current_time('Y-m-d-H-i-s');
        $rotated_file = str_replace('.log', '-' . $timestamp . '.log', $this->current_log_file);
        
        if (rename($this->current_log_file, $rotated_file)) {
            $this->current_log_file = null; // Reset to create new file
        }
    }
    
    /**
     * Get client IP address
     * 
     * @return string
     */
    private function get_client_ip() {
        $ip_keys = array('HTTP_CF_CONNECTING_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR');
        
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
     * Get log files
     * 
     * @return array
     */
    public function get_log_files() {
        if (!is_dir($this->log_dir)) {
            return array();
        }
        
        $files = glob($this->log_dir . '*.log');
        rsort($files); // Sort by modification time, newest first
        
        return $files;
    }
    
    /**
     * Get log file contents
     * 
     * @param string $file_path
     * @param int $limit
     * @return string|false
     */
    public function get_log_contents($file_path, $limit = 100) {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return false;
        }
        
        $lines = file($file_path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            return false;
        }
        
        if ($limit > 0 && count($lines) > $limit) {
            $lines = array_slice($lines, -$limit);
        }
        
        return implode("\n", $lines);
    }
    
    /**
     * Clean old log files
     * 
     * @param int $retention_days
     * @return int Number of files deleted
     */
    public function clean_old_logs($retention_days = 30) {
        if (!is_dir($this->log_dir)) {
            return 0;
        }
        
        $files = glob($this->log_dir . '*.log');
        $cutoff_time = time() - ($retention_days * 24 * 60 * 60);
        $deleted_count = 0;
        
        foreach ($files as $file) {
            if (filemtime($file) < $cutoff_time) {
                if (unlink($file)) {
                    $deleted_count++;
                }
            }
        }
        
        return $deleted_count;
    }
    
    /**
     * Get log statistics
     * 
     * @return array
     */
    public function get_log_statistics() {
        $files = $this->get_log_files();
        $total_size = 0;
        $total_entries = 0;
        
        foreach ($files as $file) {
            if (file_exists($file)) {
                $total_size += filesize($file);
                $content = file_get_contents($file);
                if ($content) {
                    $total_entries += substr_count($content, 'timestamp');
                }
            }
        }
        
        return array(
            'total_files' => count($files),
            'total_size' => $total_size,
            'total_size_formatted' => size_format($total_size),
            'total_entries' => $total_entries,
            'oldest_file' => !empty($files) ? basename(end($files)) : null,
            'newest_file' => !empty($files) ? basename($files[0]) : null
        );
    }
}
