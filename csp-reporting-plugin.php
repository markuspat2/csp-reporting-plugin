<?php
/**
 * Plugin Name: CSP Reporting Plugin
 * Plugin URI: https://example.com/csp-reporting-plugin
 * Description: A WordPress plugin for Content Security Policy (CSP) report-only headers with server-side logging capabilities.
 * Version: 1.0.0
 * Author: Your Name
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: csp-reporting
 * Domain Path: /languages
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('CSP_REPORTING_VERSION', '1.0.0');
define('CSP_REPORTING_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('CSP_REPORTING_PLUGIN_URL', plugin_dir_url(__FILE__));
define('CSP_REPORTING_LOG_DIR', WP_CONTENT_DIR . '/csp-reports/');

// Include required files
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-logger.php';
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-admin.php';
require_once CSP_REPORTING_PLUGIN_DIR . 'includes/class-csp-reporter.php';

/**
 * Main plugin class
 */
class CSP_Reporting_Plugin {
    
    private static $instance = null;
    private $logger;
    private $admin;
    private $reporter;
    
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
        add_action('init', array($this, 'init'));
        add_action('plugins_loaded', array($this, 'load_textdomain'));
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }
    
    /**
     * Initialize plugin
     */
    public function init() {
        $this->logger = new CSP_Logger();
        $this->admin = new CSP_Admin();
        $this->reporter = new CSP_Reporter();
        
        // Add CSP headers
        add_action('wp_head', array($this, 'add_csp_headers'), 1);
        add_action('admin_head', array($this, 'add_csp_headers'), 1);
        
        // Handle CSP reports
        add_action('wp_ajax_csp_report', array($this, 'handle_csp_report'));
        add_action('wp_ajax_nopriv_csp_report', array($this, 'handle_csp_report'));
        
        // Add custom endpoint for CSP reports
        add_action('init', array($this, 'add_csp_endpoint'));
        add_action('init', array($this, 'maybe_flush_rewrite_rules'));
        add_action('template_redirect', array($this, 'handle_csp_endpoint'));
        
        // Add admin notices
        add_action('admin_notices', array($this, 'show_admin_notices'));
        
        // Add debug functionality
        add_action('init', array($this, 'debug_rewrite_rules'));
    }
    
    /**
     * Load plugin textdomain
     */
    public function load_textdomain() {
        load_plugin_textdomain('csp-reporting', false, dirname(plugin_basename(__FILE__)) . '/languages');
    }
    
    /**
     * Plugin activation
     */
    public function activate() {
        // Create log directory
        $this->create_log_directory();
        
        // Set default options
        $default_options = array(
            'csp_enabled' => true,
            'csp_policy' => "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self';",
            'log_retention_days' => 30,
            'log_max_size' => 10485760, // 10MB
            'enable_admin_notices' => true
        );
        
        add_option('csp_reporting_options', $default_options);
        
        // Schedule cleanup task
        if (!wp_next_scheduled('csp_cleanup_logs')) {
            wp_schedule_event(time(), 'daily', 'csp_cleanup_logs');
        }
        
        // Flush rewrite rules for CSP endpoint
        flush_rewrite_rules();
    }
    
    /**
     * Plugin deactivation
     */
    public function deactivate() {
        // Clear scheduled tasks
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
     * Add CSP headers
     */
    public function add_csp_headers() {
        $options = get_option('csp_reporting_options', array());
        
        if (empty($options['csp_enabled'])) {
            return;
        }
        
        $policy = !empty($options['csp_policy']) ? $options['csp_policy'] : '';
        $report_uri = home_url('/csp-report-endpoint/');
        
        if (!empty($policy)) {
            $csp_header = "Content-Security-Policy-Report-Only: {$policy}; report-uri {$report_uri}";
            header($csp_header);
        }
    }
    
    /**
     * Add CSP report endpoint
     */
    public function add_csp_endpoint() {
        add_rewrite_rule('^csp-report-endpoint/?$', 'index.php?csp_report=1', 'top');
        add_rewrite_tag('%csp_report%', '([^&]+)');
    }
    
    /**
     * Flush rewrite rules if needed
     */
    public function maybe_flush_rewrite_rules() {
        $version = get_option('csp_reporting_rewrite_version');
        if ($version !== CSP_REPORTING_VERSION) {
            flush_rewrite_rules();
            update_option('csp_reporting_rewrite_version', CSP_REPORTING_VERSION);
        }
    }
    
    /**
     * Handle CSP report endpoint
     */
    public function handle_csp_endpoint() {
        // Check for rewrite rule match
        if (get_query_var('csp_report')) {
            $this->reporter->handle_report();
            exit;
        }
        
        // Fallback: Check URL directly
        $request_uri = $_SERVER['REQUEST_URI'];
        if (strpos($request_uri, '/csp-report-endpoint/') !== false || 
            strpos($request_uri, '/csp-report-endpoint') !== false) {
            $this->reporter->handle_report();
            exit;
        }
    }
    
    /**
     * Handle CSP report via AJAX
     */
    public function handle_csp_report() {
        $this->reporter->handle_report();
        wp_die();
    }
    
    /**
     * Show admin notices
     */
    public function show_admin_notices() {
        if (is_admin() && current_user_can('manage_options')) {
            $this->admin->show_admin_notices();
        }
    }
    
    /**
     * Debug rewrite rules (for troubleshooting)
     */
    public function debug_rewrite_rules() {
        if (current_user_can('manage_options') && isset($_GET['csp_debug_rewrite'])) {
            global $wp_rewrite;
            echo '<pre>';
            echo "Rewrite Rules:\n";
            print_r($wp_rewrite->wp_rewrite_rules());
            echo "\nQuery Vars:\n";
            print_r($GLOBALS['wp']->query_vars);
            echo "\nRequest URI: " . $_SERVER['REQUEST_URI'] . "\n";
            echo "\nCSP Report Query Var: " . get_query_var('csp_report') . "\n";
            echo '</pre>';
            exit;
        }
    }
}

// Initialize the plugin
CSP_Reporting_Plugin::get_instance();

// Cleanup hook
add_action('csp_cleanup_logs', 'csp_cleanup_old_logs');

/**
 * Cleanup old log files
 */
function csp_cleanup_old_logs() {
    $options = get_option('csp_reporting_options', array());
    $retention_days = !empty($options['log_retention_days']) ? intval($options['log_retention_days']) : 30;
    
    if (is_dir(CSP_REPORTING_LOG_DIR)) {
        $files = glob(CSP_REPORTING_LOG_DIR . '*.log');
        $cutoff_time = time() - ($retention_days * 24 * 60 * 60);
        
        foreach ($files as $file) {
            if (filemtime($file) < $cutoff_time) {
                unlink($file);
            }
        }
    }
}
