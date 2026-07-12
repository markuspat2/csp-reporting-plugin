<?php
/**
 * Plugin Name: CSP Reporting Plugin
 * Plugin URI: https://github.com/markuspat2/csp-reporting-plugin
 * Description: Content Security Policy (CSP) headers with violation reporting, logging, and analysis for WordPress.
 * Version: 2.0.0
 * Author: Matchbox Design Group
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: csp-reporting
 * Domain Path: /languages
 * Requires at least: 5.9
 * Requires PHP: 7.4
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('CSP_REPORTING_VERSION', '2.0.0');
define('CSP_REPORTING_PLUGIN_FILE', __FILE__);
define('CSP_REPORTING_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('CSP_REPORTING_PLUGIN_URL', plugin_dir_url(__FILE__));
define('CSP_REPORTING_LOG_DIR', WP_CONTENT_DIR . '/csp-reports/');

// Include required files
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-utils.php';
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-logger.php';
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-admin.php';
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-reporter.php';

/**
 * Main plugin class
 */
class CSP_Reporting_Plugin {

    private static $instance = null;

    /**
     * @var CSP_Logger
     */
    public $logger;

    /**
     * @var CSP_Admin|null
     */
    public $admin;

    /**
     * @var CSP_Reporter
     */
    public $reporter;

    /**
     * Get singleton instance
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct() {
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));

        add_action('plugins_loaded', array($this, 'setup'));
    }

    /**
     * Set up plugin components and hooks.
     *
     * Runs on plugins_loaded so every hook below is registered before its
     * target fires (registering hooks from inside their own hook, as 1.x did,
     * silently skips them).
     */
    public function setup() {
        load_plugin_textdomain('csp-reporting', false, dirname(plugin_basename(__FILE__)) . '/languages');

        $this->logger = new CSP_Logger();
        $this->reporter = new CSP_Reporter($this->logger);

        if (is_admin()) {
            $this->admin = new CSP_Admin($this->logger, $this->reporter);
        }

        // Report endpoint: wp-json/csp-reporting/v1/report
        add_action('rest_api_init', array($this->reporter, 'register_routes'));

        // Send CSP headers before any output.
        add_action('send_headers', array($this, 'send_csp_headers'));
        add_action('admin_init', array($this, 'maybe_send_admin_csp_headers'), 1);

        // Scheduled log cleanup.
        add_action('csp_cleanup_logs', array($this, 'cleanup_old_logs'));
    }

    /**
     * Plugin activation
     */
    public function activate() {
        // Create log directory
        $this->create_log_directory();

        // Set default options (only added if missing)
        $default_options = array(
            'csp_enabled' => true,
            'csp_policy' => "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self';",
            'csp_admin_pages' => false,
            'log_retention_days' => 30,
            'log_max_size' => 10485760, // 10MB
            'enable_admin_notices' => true,
            'purge_logs_on_uninstall' => false,
        );

        add_option('csp_reporting_options', $default_options);

        // Schedule cleanup task
        if (!wp_next_scheduled('csp_cleanup_logs')) {
            wp_schedule_event(time(), 'daily', 'csp_cleanup_logs');
        }

        // The 1.x rewrite endpoint is gone; drop its stale rules and marker.
        delete_option('csp_reporting_rewrite_version');
        flush_rewrite_rules();
    }

    /**
     * Plugin deactivation
     */
    public function deactivate() {
        wp_clear_scheduled_hook('csp_cleanup_logs');
    }

    /**
     * Create log directory
     */
    private function create_log_directory() {
        if (!file_exists(CSP_REPORTING_LOG_DIR)) {
            wp_mkdir_p(CSP_REPORTING_LOG_DIR);

            // Create .htaccess to protect log files
            $htaccess_content = "Order Deny,Allow\nDeny from all\n";
            file_put_contents(CSP_REPORTING_LOG_DIR . '.htaccess', $htaccess_content);

            // Create index.php to prevent directory listing
            file_put_contents(CSP_REPORTING_LOG_DIR . 'index.php', '<?php // Silence is golden');
        }
    }

    /**
     * Send CSP headers on frontend requests.
     *
     * Hooked to send_headers, which fires before any body output — wp_head
     * (used in 1.x) fires mid-document, when header() is already a no-op.
     */
    public function send_csp_headers() {
        $this->output_csp_header();
    }

    /**
     * Send CSP headers on admin pages when enabled.
     */
    public function maybe_send_admin_csp_headers() {
        $options = get_option('csp_reporting_options', array());

        if (empty($options['csp_admin_pages'])) {
            return;
        }

        $this->output_csp_header();
    }

    /**
     * Build and send the Content-Security-Policy-Report-Only header.
     */
    private function output_csp_header() {
        if (headers_sent()) {
            return;
        }

        $options = get_option('csp_reporting_options', array());

        if (empty($options['csp_enabled'])) {
            return;
        }

        $policy = !empty($options['csp_policy']) ? trim($options['csp_policy']) : '';

        if (empty($policy)) {
            return;
        }

        // Strip line breaks (invalid in headers) and any hand-written
        // report-uri — the plugin appends its own endpoint.
        $policy = preg_replace('/\s+/', ' ', $policy);
        $policy = preg_replace('/;?\s*report-uri[^;]*/i', '', $policy);
        $policy = rtrim(trim($policy), ';');

        $report_url = CSP_Utils::get_report_endpoint_url();

        header(sprintf('Content-Security-Policy-Report-Only: %s; report-uri %s', $policy, $report_url));
    }

    /**
     * Cleanup old log files (daily cron)
     */
    public function cleanup_old_logs() {
        $options = get_option('csp_reporting_options', array());
        $retention_days = !empty($options['log_retention_days']) ? intval($options['log_retention_days']) : 30;

        $this->logger->clean_old_logs($retention_days);
    }
}

// Initialize the plugin
CSP_Reporting_Plugin::get_instance();
