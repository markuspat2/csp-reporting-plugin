<?php
/**
 * Plugin Name: CSP Reporting Plugin
 * Plugin URI: https://github.com/markuspat2/csp-reporting-plugin
 * Description: Content Security Policy (CSP) headers with violation reporting, logging, and analysis for WordPress.
 * Version: 2.2.0
 * Author: Matchbox Design Group
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: csp-reporting
 * Domain Path: /languages
 * Requires at least: 5.9
 * Requires PHP: 7.4
 */

// Prevent direct access
if ( ! defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('CSP_REPORTING_VERSION', '2.2.0');
define('CSP_REPORTING_PLUGIN_FILE', __FILE__);
define('CSP_REPORTING_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('CSP_REPORTING_PLUGIN_URL', plugin_dir_url(__FILE__));
define('CSP_REPORTING_LOG_DIR', WP_CONTENT_DIR . '/csp-reports/');

// Include required files
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-utils.php';
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-nonce.php';
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/csp-template-functions.php';
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-policy.php';
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-database.php';
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-logger.php';
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-notifications.php';
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
     * @var CSP_Database
     */
    public $database;

    /**
     * @var CSP_Notifications
     */
    public $notifications;

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
        register_activation_hook(__FILE__, array( $this, 'activate' ));
        register_deactivation_hook(__FILE__, array( $this, 'deactivate' ));

        add_action('plugins_loaded', array( $this, 'setup' ));
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

        $this->logger        = new CSP_Logger();
        $this->database      = new CSP_Database();
        $this->reporter      = new CSP_Reporter($this->logger, $this->database);
        $this->notifications = new CSP_Notifications($this->database);

        // Schema check on every request (one autoloaded option read) so the
        // report endpoint never writes before an admin visit upgrades the table.
        $this->database->maybe_upgrade_schema();

        if (is_admin()) {
            $this->database->maybe_upgrade($this->logger);
            CSP_Notifications::schedule(); // No-op when already scheduled; covers upgrades without re-activation.
            $this->admin = new CSP_Admin($this->logger, $this->reporter, $this->database);
        }

        if (defined('WP_CLI') && WP_CLI) {
            require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-cli.php';
            WP_CLI::add_command('csp', new CSP_CLI($this->database, $this->reporter));
        }

        // Report endpoint: wp-json/csp-reporting/v1/report
        add_action('rest_api_init', array( $this->reporter, 'register_routes' ));

        // Send CSP headers before any output.
        add_action('send_headers', array( $this, 'send_csp_headers' ));
        add_action('admin_init', array( $this, 'maybe_send_admin_csp_headers' ), 1);

        // Nonce mode is front-end only; wp-admin is never stamped.
        if ( ! is_admin()) {
            $this->maybe_register_nonce_stamping();
        }

        // Scheduled log cleanup.
        add_action('csp_cleanup_logs', array( $this, 'cleanup_old_logs' ));
    }

    /**
     * Plugin activation
     */
    public function activate() {
        // Create log directory
        $this->create_log_directory();

        // Create the violations table.
        CSP_Database::install();

        // Set default options (only added if missing)
        $default_policy = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self';";

        $default_options = array(
            'csp_enabled' => true,
            'csp_policy' => $default_policy,
            'csp_policy_directives' => CSP_Policy::parse_policy_text($default_policy),
            'csp_mode' => CSP_Policy::MODE_REPORT_ONLY,
            'csp_test_policy' => '',
            'csp_admin_pages' => false,
            'csp_nonce_enforce' => false,
            'csp_nonce_report_only' => false,
            'csp_strict_dynamic' => false,
            'csp_report_sample' => false,
            'log_retention_days' => 30,
            'log_max_size' => 10485760, // 10MB
            'file_logging_enabled' => false,
            'store_client_ip' => false,
            'rate_limit_per_minute' => 30,
            'ignore_patterns' => CSP_Utils::default_ignore_patterns(),
            'enable_admin_notices' => true,
            'purge_logs_on_uninstall' => false,
        );

        add_option('csp_reporting_options', $default_options);

        // Schedule cleanup task
        if ( ! wp_next_scheduled('csp_cleanup_logs')) {
            wp_schedule_event(time(), 'daily', 'csp_cleanup_logs');
        }

        // Schedule notification digest
        CSP_Notifications::schedule();

        // The 1.x rewrite endpoint is gone; drop its stale rules and marker.
        delete_option('csp_reporting_rewrite_version');
        flush_rewrite_rules();
    }

    /**
     * Plugin deactivation
     */
    public function deactivate() {
        wp_clear_scheduled_hook('csp_cleanup_logs');
        CSP_Notifications::unschedule();
    }

    /**
     * Create log directory
     */
    private function create_log_directory() {
        if ( ! file_exists(CSP_REPORTING_LOG_DIR)) {
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
        $this->output_csp_header(true);
    }

    /**
     * Stamp the request's nonce onto every script WordPress prints when a
     * header sent on this request carries the nonce.
     *
     * Since WordPress 6.4 (the minimum for nonce mode) every WP_Scripts tag
     * — enqueued src, inline before/after, wp_localize_script data,
     * translations — and script modules / the import map go through these
     * two filters. Scripts printed any other way (hard-coded in templates,
     * echoed by plugins) are deliberately not stamped: blanket output
     * stamping would bless injected scripts too. Those show up as
     * violations instead, and are fixed with csp_nonce_attr().
     */
    public function maybe_register_nonce_stamping() {
        $policy = new CSP_Policy();

        if ( ! $policy->is_nonce_active()) {
            return;
        }

        add_filter('wp_script_attributes', array( 'CSP_Nonce', 'add_to_attributes' ));
        add_filter('wp_inline_script_attributes', array( 'CSP_Nonce', 'add_to_attributes' ));
    }

    /**
     * Send CSP headers on admin pages when enabled.
     *
     * Nonce mode is front-end only: admin headers never carry a nonce, and
     * admin scripts are never stamped.
     */
    public function maybe_send_admin_csp_headers() {
        $options = get_option('csp_reporting_options', array());

        if (empty($options['csp_admin_pages'])) {
            return;
        }

        $this->output_csp_header(false);
    }

    /**
     * Build and send the CSP header(s) for the configured mode
     * (report-only, enforce, or both).
     *
     * @param bool $allow_nonce Whether nonce mode may apply to this request.
     */
    private function output_csp_header( $allow_nonce ) {
        if (headers_sent()) {
            return;
        }

        $options = get_option('csp_reporting_options', array());

        if (empty($options['csp_enabled'])) {
            return;
        }

        $policy  = new CSP_Policy();
        $headers = $policy->get_headers(CSP_Utils::get_report_endpoint_url(), $allow_nonce);

        foreach ($headers as $name => $value) {
            header($name . ': ' . $value);
        }
    }

    /**
     * Cleanup old data (daily cron): file logs and database rows past the
     * retention window.
     */
    public function cleanup_old_logs() {
        $options        = get_option('csp_reporting_options', array());
        $retention_days = ! empty($options['log_retention_days']) ? intval($options['log_retention_days']) : 30;

        $this->logger->clean_old_logs($retention_days);
        $this->database->prune($retention_days);
    }
}

// Initialize the plugin
CSP_Reporting_Plugin::get_instance();
