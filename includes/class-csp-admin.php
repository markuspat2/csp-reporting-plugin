<?php
/**
 * CSP Admin Class
 * 
 * Handles the WordPress admin interface for CSP reporting plugin
 */

if (!defined('ABSPATH')) {
    exit;
}

class CSP_Admin {

    private $logger;
    private $reporter;
    private $database;

    /**
     * Constructor
     *
     * @param CSP_Logger|null $logger
     * @param CSP_Reporter|null $reporter
     * @param CSP_Database|null $database
     */
    public function __construct($logger = null, $reporter = null, $database = null) {
        $this->logger = $logger instanceof CSP_Logger ? $logger : new CSP_Logger();
        $this->database = $database instanceof CSP_Database ? $database : new CSP_Database();
        $this->reporter = $reporter instanceof CSP_Reporter ? $reporter : new CSP_Reporter($this->logger, $this->database);

        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('admin_notices', array($this, 'show_admin_notices'));
        add_action('wp_ajax_csp_download_log', array($this, 'download_log_file'));
        add_action('wp_ajax_csp_clear_logs', array($this, 'clear_log_files'));
        add_action('wp_ajax_csp_get_log_content', array($this, 'get_log_content'));
        add_action('wp_ajax_csp_send_test_report', array($this, 'send_test_report'));
    }
    
    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        add_options_page(
            __('CSP Reporting', 'csp-reporting'),
            __('CSP Reporting', 'csp-reporting'),
            'manage_options',
            'csp-reporting',
            array($this, 'admin_page')
        );
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        register_setting('csp_reporting_options', 'csp_reporting_options', array($this, 'sanitize_options'));
        
        add_settings_section(
            'csp_general_section',
            __('General Settings', 'csp-reporting'),
            array($this, 'general_section_callback'),
            'csp-reporting'
        );
        
        add_settings_field(
            'csp_enabled',
            __('Enable CSP Reporting', 'csp-reporting'),
            array($this, 'csp_enabled_callback'),
            'csp-reporting',
            'csp_general_section'
        );
        
        add_settings_field(
            'csp_policy',
            __('CSP Policy', 'csp-reporting'),
            array($this, 'csp_policy_callback'),
            'csp-reporting',
            'csp_general_section'
        );

        add_settings_field(
            'csp_admin_pages',
            __('Apply to Admin Pages', 'csp-reporting'),
            array($this, 'csp_admin_pages_callback'),
            'csp-reporting',
            'csp_general_section'
        );
        
        add_settings_section(
            'csp_logging_section',
            __('Logging Settings', 'csp-reporting'),
            array($this, 'logging_section_callback'),
            'csp-reporting'
        );
        
        add_settings_field(
            'log_retention_days',
            __('Log Retention (Days)', 'csp-reporting'),
            array($this, 'log_retention_callback'),
            'csp-reporting',
            'csp_logging_section'
        );
        
        add_settings_field(
            'log_max_size',
            __('Max Log File Size (Bytes)', 'csp-reporting'),
            array($this, 'log_max_size_callback'),
            'csp-reporting',
            'csp_logging_section'
        );

        add_settings_field(
            'file_logging_enabled',
            __('Raw File Logging', 'csp-reporting'),
            array($this, 'file_logging_callback'),
            'csp-reporting',
            'csp_logging_section'
        );

        add_settings_field(
            'rate_limit_per_minute',
            __('Rate Limit (Reports/Minute/IP)', 'csp-reporting'),
            array($this, 'rate_limit_callback'),
            'csp-reporting',
            'csp_logging_section'
        );

        add_settings_field(
            'ignore_patterns',
            __('Ignore Patterns', 'csp-reporting'),
            array($this, 'ignore_patterns_callback'),
            'csp-reporting',
            'csp_logging_section'
        );
        
        add_settings_field(
            'enable_admin_notices',
            __('Enable Admin Notices', 'csp-reporting'),
            array($this, 'admin_notices_callback'),
            'csp-reporting',
            'csp_logging_section'
        );

        add_settings_field(
            'purge_logs_on_uninstall',
            __('Purge Logs on Uninstall', 'csp-reporting'),
            array($this, 'purge_logs_callback'),
            'csp-reporting',
            'csp_logging_section'
        );
    }
    
    /**
     * Enqueue admin scripts and styles
     */
    public function enqueue_admin_scripts($hook) {
        if ($hook !== 'settings_page_csp-reporting') {
            return;
        }
        
        wp_enqueue_style('csp-admin-style', CSP_REPORTING_PLUGIN_URL . 'assets/admin.css', array(), CSP_REPORTING_VERSION);
        wp_enqueue_script('csp-admin-script', CSP_REPORTING_PLUGIN_URL . 'assets/admin.js', array('jquery'), CSP_REPORTING_VERSION, true);
        
        wp_localize_script('csp-admin-script', 'csp_admin_ajax', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('csp_admin_nonce'),
            'strings' => array(
                'confirm_clear_logs' => __('Are you sure you want to clear all log files? This action cannot be undone.', 'csp-reporting'),
                'logs_cleared' => __('Log files have been cleared successfully.', 'csp-reporting'),
                'error_occurred' => __('An error occurred. Please try again.', 'csp-reporting')
            )
        ));
    }
    
    /**
     * Admin page callback: routes between the Settings and Violations tabs.
     */
    public function admin_page() {
        $active_tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'settings';

        if ($active_tab === 'violations') {
            $this->render_violations_page();
            return;
        }

        $options = get_option('csp_reporting_options', array());
        $log_stats = $this->logger->get_log_statistics();
        $log_files = $this->logger->get_log_files();
        $db_stats = $this->database->get_stats(7);

        include CSP_REPORTING_PLUGIN_DIR . 'templates/admin-page.php';
    }

    /**
     * Render the tab navigation shared by both admin screens.
     *
     * @param string $active
     */
    public function render_tabs($active) {
        $tabs = array(
            'settings' => __('Settings', 'csp-reporting'),
            'violations' => __('Violations', 'csp-reporting'),
        );

        echo '<h2 class="nav-tab-wrapper">';
        foreach ($tabs as $slug => $label) {
            printf(
                '<a href="%s" class="nav-tab %s">%s</a>',
                esc_url(add_query_arg(array('page' => 'csp-reporting', 'tab' => $slug), admin_url('options-general.php'))),
                $active === $slug ? 'nav-tab-active' : '',
                esc_html($label)
            );
        }
        echo '</h2>';
    }

    /**
     * Render the violations list table screen.
     */
    private function render_violations_page() {
        require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-list-table.php';

        $list_table = new CSP_Violations_List_Table($this->database);

        // Handle bulk actions before rendering.
        if ($list_table->current_action() === 'delete' && !empty($_REQUEST['violation_ids'])) {
            check_admin_referer('bulk-csp_violations');

            if (current_user_can('manage_options')) {
                $deleted = $this->database->delete_violations((array) $_REQUEST['violation_ids']);
                add_settings_error(
                    'csp_reporting',
                    'violations_deleted',
                    sprintf(_n('%d violation deleted.', '%d violations deleted.', $deleted, 'csp-reporting'), $deleted),
                    'success'
                );
            }
        }

        $list_table->prepare_items();

        include CSP_REPORTING_PLUGIN_DIR . 'templates/violations-page.php';
    }
    
    /**
     * Sanitize options
     */
    public function sanitize_options($input) {
        $sanitized = array();
        
        $sanitized['csp_enabled'] = !empty($input['csp_enabled']) ? 1 : 0;
        $sanitized['csp_policy'] = sanitize_textarea_field($input['csp_policy']);
        $sanitized['csp_admin_pages'] = !empty($input['csp_admin_pages']) ? 1 : 0;
        $sanitized['log_retention_days'] = intval($input['log_retention_days']);
        $sanitized['log_max_size'] = intval($input['log_max_size']);
        $sanitized['file_logging_enabled'] = !empty($input['file_logging_enabled']) ? 1 : 0;
        $sanitized['rate_limit_per_minute'] = isset($input['rate_limit_per_minute']) ? max(0, intval($input['rate_limit_per_minute'])) : CSP_Reporter::RATE_LIMIT_PER_MINUTE;
        $sanitized['enable_admin_notices'] = !empty($input['enable_admin_notices']) ? 1 : 0;
        $sanitized['purge_logs_on_uninstall'] = !empty($input['purge_logs_on_uninstall']) ? 1 : 0;

        // One pattern per line; empty lines dropped.
        $patterns = isset($input['ignore_patterns']) ? sanitize_textarea_field($input['ignore_patterns']) : '';
        $sanitized['ignore_patterns'] = array_values(array_filter(array_map('trim', preg_split('/[\r\n]+/', $patterns))));
        
        // Validate log retention days
        if ($sanitized['log_retention_days'] < 1) {
            $sanitized['log_retention_days'] = 30;
        }
        
        // Validate log max size (minimum 1MB)
        if ($sanitized['log_max_size'] < 1048576) {
            $sanitized['log_max_size'] = 10485760; // 10MB
        }
        
        return $sanitized;
    }
    
    /**
     * Section callbacks
     */
    public function general_section_callback() {
        echo '<p>' . __('Configure your Content Security Policy settings.', 'csp-reporting') . '</p>';
    }
    
    public function logging_section_callback() {
        echo '<p>' . __('Configure logging behavior and file management.', 'csp-reporting') . '</p>';
    }
    
    /**
     * Field callbacks
     */
    public function csp_enabled_callback() {
        $options = get_option('csp_reporting_options', array());
        $enabled = !empty($options['csp_enabled']) ? 1 : 0;
        echo '<input type="checkbox" name="csp_reporting_options[csp_enabled]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . __('Enable CSP report-only headers on your site.', 'csp-reporting') . '</p>';
    }
    
    public function csp_policy_callback() {
        $options = get_option('csp_reporting_options', array());
        $policy = !empty($options['csp_policy']) ? $options['csp_policy'] : '';
        echo '<textarea name="csp_reporting_options[csp_policy]" rows="5" cols="80" class="large-text code">' . esc_textarea($policy) . '</textarea>';
        echo '<p class="description">' . __('Enter your Content Security Policy directives. Use semicolons to separate directives.', 'csp-reporting') . '</p>';
    }
    
    public function log_retention_callback() {
        $options = get_option('csp_reporting_options', array());
        $retention = !empty($options['log_retention_days']) ? intval($options['log_retention_days']) : 30;
        echo '<input type="number" name="csp_reporting_options[log_retention_days]" value="' . esc_attr($retention) . '" min="1" max="365" />';
        echo '<p class="description">' . __('Number of days to keep log files before automatic cleanup.', 'csp-reporting') . '</p>';
    }
    
    public function log_max_size_callback() {
        $options = get_option('csp_reporting_options', array());
        $max_size = !empty($options['log_max_size']) ? intval($options['log_max_size']) : 10485760;
        echo '<input type="number" name="csp_reporting_options[log_max_size]" value="' . esc_attr($max_size) . '" min="1048576" step="1048576" />';
        echo '<p class="description">' . __('Maximum size of a single log file in bytes. Files will be rotated when this size is reached.', 'csp-reporting') . '</p>';
    }
    
    public function admin_notices_callback() {
        $options = get_option('csp_reporting_options', array());
        $enabled = !empty($options['enable_admin_notices']) ? 1 : 0;
        echo '<input type="checkbox" name="csp_reporting_options[enable_admin_notices]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . __('Show admin notices for important CSP events.', 'csp-reporting') . '</p>';
    }

    public function file_logging_callback() {
        $options = get_option('csp_reporting_options', array());
        $enabled = !empty($options['file_logging_enabled']) ? 1 : 0;
        echo '<input type="checkbox" name="csp_reporting_options[file_logging_enabled]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . __('Also write raw reports to log files in wp-content/csp-reports/. The violations database is the primary store; file logs are for external tooling.', 'csp-reporting') . '</p>';
    }

    public function rate_limit_callback() {
        $options = get_option('csp_reporting_options', array());
        $limit = isset($options['rate_limit_per_minute']) ? intval($options['rate_limit_per_minute']) : CSP_Reporter::RATE_LIMIT_PER_MINUTE;
        echo '<input type="number" name="csp_reporting_options[rate_limit_per_minute]" value="' . esc_attr($limit) . '" min="0" max="1000" />';
        echo '<p class="description">' . __('Maximum reports accepted per minute from a single IP. 0 disables the limit.', 'csp-reporting') . '</p>';
    }

    public function ignore_patterns_callback() {
        $patterns = CSP_Utils::get_ignore_patterns();
        echo '<textarea name="csp_reporting_options[ignore_patterns]" rows="6" cols="60" class="large-text code">' . esc_textarea(implode("\n", $patterns)) . '</textarea>';
        echo '<p class="description">' . __('One pattern per line. Reports whose blocked URI or source file contains a pattern are dropped. Defaults cover browser-extension noise.', 'csp-reporting') . '</p>';
    }

    public function csp_admin_pages_callback() {
        $options = get_option('csp_reporting_options', array());
        $enabled = !empty($options['csp_admin_pages']) ? 1 : 0;
        echo '<input type="checkbox" name="csp_reporting_options[csp_admin_pages]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . __('Also send the CSP header on wp-admin pages. Leave disabled unless your policy is known to be admin-safe.', 'csp-reporting') . '</p>';
    }

    public function purge_logs_callback() {
        $options = get_option('csp_reporting_options', array());
        $enabled = !empty($options['purge_logs_on_uninstall']) ? 1 : 0;
        echo '<input type="checkbox" name="csp_reporting_options[purge_logs_on_uninstall]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . __('Delete the log directory and all violation data when the plugin is uninstalled.', 'csp-reporting') . '</p>';
    }
    
    /**
     * Download log file via AJAX
     */
    public function download_log_file() {
        check_ajax_referer('csp_admin_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'csp-reporting'));
        }
        
        $file_path = sanitize_text_field($_POST['file_path']);
        
        if (!file_exists($file_path) || !is_readable($file_path)) {
            wp_die(__('File not found or not readable.', 'csp-reporting'));
        }
        
        // Verify the file is within the log directory
        $log_dir = realpath(CSP_REPORTING_LOG_DIR);
        $file_path = realpath($file_path);
        
        if (strpos($file_path, $log_dir) !== 0) {
            wp_die(__('Invalid file path.', 'csp-reporting'));
        }
        
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
        header('Content-Length: ' . filesize($file_path));
        
        readfile($file_path);
        exit;
    }
    
    /**
     * Clear log files via AJAX
     */
    public function clear_log_files() {
        check_ajax_referer('csp_admin_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'csp-reporting'));
        }
        
        $files = $this->logger->get_log_files();
        $deleted_count = 0;
        
        foreach ($files as $file) {
            if (unlink($file)) {
                $deleted_count++;
            }
        }
        
        wp_send_json_success(array(
            'message' => sprintf(__('%d log files have been cleared.', 'csp-reporting'), $deleted_count)
        ));
    }
    
    /**
     * Get log file content via AJAX
     */
    public function get_log_content() {
        check_ajax_referer('csp_admin_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'csp-reporting'));
        }
        
        $file_path = sanitize_text_field($_POST['file_path']);
        
        if (!file_exists($file_path) || !is_readable($file_path)) {
            wp_send_json_error(array(
                'message' => __('File not found or not readable.', 'csp-reporting')
            ));
        }
        
        // Verify the file is within the log directory
        $log_dir = realpath(CSP_REPORTING_LOG_DIR);
        $file_path = realpath($file_path);
        
        if (strpos($file_path, $log_dir) !== 0) {
            wp_send_json_error(array(
                'message' => __('Invalid file path.', 'csp-reporting')
            ));
        }
        
        $content = $this->logger->get_log_contents($file_path, 1000); // Limit to 1000 lines
        
        if ($content === false) {
            wp_send_json_error(array(
                'message' => __('Failed to read file content.', 'csp-reporting')
            ));
        }
        
        wp_send_json_success(array(
            'content' => $content
        ));
    }
    
    /**
     * Send a synthetic test report through the full processing pipeline.
     *
     * Replaces the 1.x anonymous GET handler on the public endpoint, which
     * disclosed server paths to unauthenticated visitors.
     */
    public function send_test_report() {
        check_ajax_referer('csp_admin_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array(
                'message' => __('You do not have sufficient permissions to do this.', 'csp-reporting'),
            ));
        }

        $this->reporter->process_report($this->reporter->create_test_report());

        wp_send_json_success(array(
            'message' => __('Test report processed. Check the logs for the new entry.', 'csp-reporting'),
        ));
    }

    /**
     * Show admin notices
     */
    public function show_admin_notices() {
        if (!current_user_can('manage_options')) {
            return;
        }

        $options = get_option('csp_reporting_options', array());

        if (empty($options['enable_admin_notices'])) {
            return;
        }

        // Only surface the summary on the plugin's own settings screen to
        // avoid nagging on every admin page.
        $screen = function_exists('get_current_screen') ? get_current_screen() : null;
        if (!$screen || $screen->id !== 'settings_page_csp-reporting') {
            return;
        }
        
        $log_stats = $this->logger->get_log_statistics();
        
        if ($log_stats['total_entries'] > 0) {
            $class = 'notice notice-info';
            $message = sprintf(
                __('CSP Reporting: %d violations logged across %d files (%s total size).', 'csp-reporting'),
                $log_stats['total_entries'],
                $log_stats['total_files'],
                $log_stats['total_size_formatted']
            );
            
            printf('<div class="%1$s"><p>%2$s <a href="%3$s">%4$s</a></p></div>', 
                esc_attr($class), 
                esc_html($message),
                admin_url('options-general.php?page=csp-reporting'),
                __('View Reports', 'csp-reporting')
            );
        }
    }
}
