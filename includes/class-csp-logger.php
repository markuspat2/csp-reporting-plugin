<?php
/**
 * CSP Logger Class
 *
 * Handles logging of CSP violation reports to files
 */

if ( ! defined('ABSPATH')) {
    exit;
}

class CSP_Logger {

    /**
     * Option holding this site's random log-file name secret.
     */
    const SECRET_OPTION = 'csp_reporting_log_secret';

    /**
     * Marker written into .htaccess so outdated copies can be recognised.
     */
    const HTACCESS_MARKER = '# CSP Reporting Plugin: deny all';

    private $log_dir;
    private $max_file_size;
    private $current_log_file;

    /**
     * Constructor
     */
    public function __construct() {
        $this->log_dir       = rtrim(CSP_REPORTING_LOG_DIR, '/\\') . '/'; // A wp-config.php value may lack the trailing slash.
        $options             = get_option('csp_reporting_options', array());
        $this->max_file_size = ! empty($options['log_max_size']) ? intval($options['log_max_size']) : 10485760; // 10MB default
    }

    /**
     * Log CSP violation report
     *
     * @param array $report_data The CSP violation report data
     * @return bool True on success, false on failure
     */
    public function log_violation( $report_data ) {
        if ( ! $this->is_valid_report($report_data)) {
            return false;
        }

        $log_entry = $this->format_log_entry($report_data);
        $log_file  = $this->get_current_log_file();

        if ( ! $log_file) {
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
    private function is_valid_report( $report_data ) {
        if ( ! is_array($report_data) || ! isset($report_data['csp-report'])) {
            return false;
        }

        $csp_report = $report_data['csp-report'];

        return isset($csp_report['document-uri'], $csp_report['violated-directive']);
    }

    /**
     * Format a log entry as one JSON object per line (NDJSON) so log files
     * can be parsed line-by-line and tailed safely.
     *
     * @param array $report_data
     * @return string
     */
    private function format_log_entry( $report_data ) {
        $options = get_option('csp_reporting_options', array());

        $log_entry = array(
            'timestamp' => current_time('Y-m-d H:i:s'),
            // Same rule as the database: IPs are personal data and are only
            // recorded when "Store Client IP Addresses" is on.
            'ip_address' => ! empty($options['store_client_ip']) ? CSP_Utils::get_client_ip() : '',
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown',
            'report_data' => $report_data,
        );

        return wp_json_encode($log_entry) . "\n";
    }

    /**
     * Read parsed entries from a log file.
     *
     * Supports both the NDJSON format written since 2.0.0 and the 1.x format
     * (pretty-printed JSON blocks separated by a line of 80 dashes).
     *
     * @param string $file_path
     * @return array[] List of decoded log entries
     */
    public function read_log_entries( $file_path ) {
        if ( ! file_exists($file_path) || ! is_readable($file_path)) {
            return array();
        }

        $content = file_get_contents($file_path);
        if ( ! $content) {
            return array();
        }

        $entries = array();

        if (strpos($content, str_repeat('-', 80)) !== false) {
            // Legacy 1.x format.
            $chunks = explode(str_repeat('-', 80), $content);
        } else {
            $chunks = explode("\n", $content);
        }

        foreach ($chunks as $chunk) {
            $chunk = trim($chunk);
            if ($chunk === '') {
                continue;
            }

            $decoded = json_decode($chunk, true);
            if (is_array($decoded)) {
                $entries[] = $decoded;
            }
        }

        return $entries;
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

        // The name carries a per-site random secret: .htaccess only protects
        // the directory on Apache, and on nginx a predictable name
        // (csp-reports-2026-10-31.log) was downloadable by anyone.
        $date     = current_time('Y-m-d');
        $log_file = $this->log_dir . 'csp-reports-' . $date . '-' . $this->get_secret() . '.log';

        // Ensure directory exists
        if ( ! file_exists($this->log_dir)) {
            if ( ! wp_mkdir_p($this->log_dir)) {
                error_log('CSP Reporting Plugin: Failed to create log directory');
                return false;
            }
            $this->protect_directory();
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
    private function should_rotate_log( $log_file ) {
        if ( ! file_exists($log_file)) {
            return false;
        }

        return filesize($log_file) >= $this->max_file_size;
    }

    /**
     * Rotate log file
     */
    private function rotate_log_file() {
        if ( ! $this->current_log_file || ! file_exists($this->current_log_file)) {
            return;
        }

        $timestamp = current_time('Y-m-d-H-i-s');
        // Only the extension: str_replace() over the whole path also hit
        // directories like /var/www/my.logistics/.
        $rotated_file = preg_replace('/\.log$/', '-' . $timestamp . '.log', $this->current_log_file);

        if (rename($this->current_log_file, $rotated_file)) {
            $this->current_log_file = null; // Reset to create new file
        }
    }

    /**
     * Get (creating on first use) this site's log-file name secret.
     *
     * @return string
     */
    private function get_secret() {
        $secret = get_option(self::SECRET_OPTION);

        if ( ! is_string($secret) || ! preg_match('/^[A-Za-z0-9]{20,}$/', $secret)) {
            $secret = wp_generate_password(24, false, false);
            update_option(self::SECRET_OPTION, $secret, false);
        }

        return $secret;
    }

    /**
     * Write the deny-all .htaccess (Apache 2.2 and 2.4 syntax) and a silent
     * index.php into the log directory, replacing an outdated .htaccess.
     */
    public function protect_directory() {
        if ( ! is_dir($this->log_dir)) {
            return;
        }

        $htaccess = $this->log_dir . '.htaccess';
        $current  = file_exists($htaccess) ? (string) file_get_contents($htaccess) : '';

        if (strpos($current, self::HTACCESS_MARKER) === false) {
            file_put_contents($htaccess, self::HTACCESS_MARKER . "\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order Deny,Allow\n    Deny from all\n</IfModule>\n");
        }

        if ( ! file_exists($this->log_dir . 'index.php')) {
            file_put_contents($this->log_dir . 'index.php', '<?php // Silence is golden');
        }
    }

    /**
     * One-time hardening of an existing log directory: refresh the
     * protection files and give log files written with predictable names
     * (before 2.2.0, including 1.x logs) this site's secret.
     *
     * @return int Files renamed.
     */
    public function harden_log_directory() {
        if ( ! is_dir($this->log_dir)) {
            return 0;
        }

        $this->protect_directory();

        $renamed = 0;

        foreach ($this->get_log_files() as $file) {
            $name = basename($file);

            // Only the old fixed patterns; names that already carry a secret
            // (this site's or, on multisite, another site's) never match.
            if ( ! preg_match('/^csp-reports-\d{4}-\d{2}-\d{2}(-\d{4}(-\d{2}){5})?\.log$/', $name)) {
                continue;
            }

            $target = $this->log_dir . substr($name, 0, -4) . '-' . $this->get_secret() . '.log';

            if ( ! file_exists($target) && rename($file, $target)) {
                ++$renamed;
            }
        }

        return $renamed;
    }

    /**
     * Get log files
     *
     * @return array
     */
    public function get_log_files() {
        if ( ! is_dir($this->log_dir)) {
            return array();
        }

        $files = (array) glob($this->log_dir . '*.log');
        rsort($files);

        return $files;
    }

    /**
     * Get log file contents
     *
     * @param string $file_path
     * @param int $limit Maximum number of entries to return (most recent first in file order)
     * @return string|false
     */
    public function get_log_contents( $file_path, $limit = 100 ) {
        if ( ! file_exists($file_path) || ! is_readable($file_path)) {
            return false;
        }

        $entries = $this->read_log_entries($file_path);

        if ($limit > 0 && count($entries) > $limit) {
            $entries = array_slice($entries, -$limit);
        }

        $lines = array();
        foreach ($entries as $entry) {
            $lines[] = wp_json_encode($entry, JSON_PRETTY_PRINT);
        }

        return implode("\n" . str_repeat('-', 40) . "\n", $lines);
    }

    /**
     * Clean old log files
     *
     * @param int $retention_days
     * @return int Number of files deleted
     */
    public function clean_old_logs( $retention_days = 30 ) {
        if ( ! is_dir($this->log_dir)) {
            return 0;
        }

        $files         = (array) glob($this->log_dir . '*.log');
        $cutoff_time   = time() - ( $retention_days * 24 * 60 * 60 );
        $deleted_count = 0;

        foreach ($files as $file) {
            if (filemtime($file) < $cutoff_time) {
                if (unlink($file)) {
                    ++$deleted_count;
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
        $files      = $this->get_log_files();
        $total_size = 0;

        // Sizes only: this runs on every settings page view, and it used to
        // read and JSON-decode every log file (up to 10 MB each) to count
        // entries nothing displayed.
        foreach ($files as $file) {
            if (file_exists($file)) {
                $total_size += filesize($file);
            }
        }

        return array(
            'total_files' => count($files),
            'total_size' => $total_size,
            'total_size_formatted' => size_format($total_size),
        );
    }
}
