<?php
/**
 * CSP Admin Class
 *
 * Handles the WordPress admin interface for CSP reporting plugin
 */

if ( ! defined('ABSPATH')) {
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
    public function __construct( $logger = null, $reporter = null, $database = null ) {
        $this->logger   = $logger instanceof CSP_Logger ? $logger : new CSP_Logger();
        $this->database = $database instanceof CSP_Database ? $database : new CSP_Database();
        $this->reporter = $reporter instanceof CSP_Reporter ? $reporter : new CSP_Reporter($this->logger, $this->database);

        add_action('admin_menu', array( $this, 'add_admin_menu' ));
        add_action('admin_init', array( $this, 'register_settings' ));
        add_action('admin_enqueue_scripts', array( $this, 'enqueue_admin_scripts' ));
        add_action('admin_notices', array( $this, 'show_admin_notices' ));
        add_action('wp_ajax_csp_download_log', array( $this, 'download_log_file' ));
        add_action('wp_ajax_csp_clear_logs', array( $this, 'clear_log_files' ));
        add_action('wp_ajax_csp_get_log_content', array( $this, 'get_log_content' ));
        add_action('wp_ajax_csp_send_test_report', array( $this, 'send_test_report' ));
        add_action('wp_ajax_csp_allow_source', array( $this, 'allow_source' ));
        add_action('wp_ajax_csp_dismiss_notice', array( $this, 'dismiss_high_severity_notice' ));
        add_action('admin_post_csp_export_violations', array( $this, 'export_violations' ));
        add_action('wp_dashboard_setup', array( $this, 'register_dashboard_widget' ));

        if (is_multisite()) {
            add_action('network_admin_menu', array( $this, 'add_network_admin_menu' ));
        }
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
            array( $this, 'admin_page' )
        );
    }

    /**
     * Register settings
     */
    public function register_settings() {
        register_setting('csp_reporting_options', 'csp_reporting_options', array( $this, 'sanitize_options' ));

        add_settings_section(
            'csp_general_section',
            __('General Settings', 'csp-reporting'),
            array( $this, 'general_section_callback' ),
            'csp-reporting'
        );

        add_settings_field(
            'csp_enabled',
            __('Enable CSP Reporting', 'csp-reporting'),
            array( $this, 'csp_enabled_callback' ),
            'csp-reporting',
            'csp_general_section'
        );

        add_settings_field(
            'csp_mode',
            __('Delivery Mode', 'csp-reporting'),
            array( $this, 'csp_mode_callback' ),
            'csp-reporting',
            'csp_general_section'
        );

        add_settings_field(
            'csp_policy',
            __('Policy Directives', 'csp-reporting'),
            array( $this, 'policy_builder_callback' ),
            'csp-reporting',
            'csp_general_section'
        );

        add_settings_field(
            'csp_admin_pages',
            __('Apply to Admin Pages', 'csp-reporting'),
            array( $this, 'csp_admin_pages_callback' ),
            'csp-reporting',
            'csp_general_section'
        );

        add_settings_section(
            'csp_logging_section',
            __('Logging Settings', 'csp-reporting'),
            array( $this, 'logging_section_callback' ),
            'csp-reporting'
        );

        add_settings_field(
            'log_retention_days',
            __('Log Retention (Days)', 'csp-reporting'),
            array( $this, 'log_retention_callback' ),
            'csp-reporting',
            'csp_logging_section'
        );

        add_settings_field(
            'log_max_size',
            __('Max Log File Size (Bytes)', 'csp-reporting'),
            array( $this, 'log_max_size_callback' ),
            'csp-reporting',
            'csp_logging_section'
        );

        add_settings_field(
            'file_logging_enabled',
            __('Raw File Logging', 'csp-reporting'),
            array( $this, 'file_logging_callback' ),
            'csp-reporting',
            'csp_logging_section'
        );

        add_settings_field(
            'rate_limit_per_minute',
            __('Rate Limit (Reports/Minute/IP)', 'csp-reporting'),
            array( $this, 'rate_limit_callback' ),
            'csp-reporting',
            'csp_logging_section'
        );

        add_settings_field(
            'ignore_patterns',
            __('Ignore Patterns', 'csp-reporting'),
            array( $this, 'ignore_patterns_callback' ),
            'csp-reporting',
            'csp_logging_section'
        );

        add_settings_field(
            'enable_admin_notices',
            __('Enable Admin Notices', 'csp-reporting'),
            array( $this, 'admin_notices_callback' ),
            'csp-reporting',
            'csp_logging_section'
        );

        add_settings_field(
            'purge_logs_on_uninstall',
            __('Purge Logs on Uninstall', 'csp-reporting'),
            array( $this, 'purge_logs_callback' ),
            'csp-reporting',
            'csp_logging_section'
        );

        add_settings_section(
            'csp_notifications_section',
            __('Notifications', 'csp-reporting'),
            array( $this, 'notifications_section_callback' ),
            'csp-reporting'
        );

        add_settings_field(
            'notify_email_enabled',
            __('Email Notifications', 'csp-reporting'),
            array( $this, 'notify_email_enabled_callback' ),
            'csp-reporting',
            'csp_notifications_section'
        );

        add_settings_field(
            'notify_email_recipients',
            __('Recipients', 'csp-reporting'),
            array( $this, 'notify_recipients_callback' ),
            'csp-reporting',
            'csp_notifications_section'
        );

        add_settings_field(
            'notify_digest_frequency',
            __('Digest Frequency', 'csp-reporting'),
            array( $this, 'notify_frequency_callback' ),
            'csp-reporting',
            'csp_notifications_section'
        );

        add_settings_field(
            'notify_immediate_high',
            __('Immediate High-Severity Alerts', 'csp-reporting'),
            array( $this, 'notify_immediate_callback' ),
            'csp-reporting',
            'csp_notifications_section'
        );

        add_settings_field(
            'notify_webhook_url',
            __('Webhook URL', 'csp-reporting'),
            array( $this, 'notify_webhook_callback' ),
            'csp-reporting',
            'csp_notifications_section'
        );
    }

    /**
     * Enqueue admin scripts and styles
     */
    public function enqueue_admin_scripts( $hook ) {
        if ($hook !== 'settings_page_csp-reporting') {
            return;
        }

        wp_enqueue_style('csp-admin-style', CSP_REPORTING_PLUGIN_URL . 'assets/admin.css', array(), CSP_REPORTING_VERSION);
        wp_enqueue_script('csp-admin-script', CSP_REPORTING_PLUGIN_URL . 'assets/admin.js', array( 'jquery' ), CSP_REPORTING_VERSION, true);
        wp_enqueue_script('csp-policy-builder', CSP_REPORTING_PLUGIN_URL . 'assets/policy-builder.js', array( 'jquery' ), CSP_REPORTING_VERSION, true);

        wp_localize_script('csp-admin-script', 'csp_admin_ajax', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('csp_admin_nonce'),
            'strings' => array(
                'confirm_clear_logs' => __('Are you sure you want to clear all log files? This action cannot be undone.', 'csp-reporting'),
                'logs_cleared' => __('Log files have been cleared successfully.', 'csp-reporting'),
                'error_occurred' => __('An error occurred. Please try again.', 'csp-reporting'),
            ),
        ));
    }

    /**
     * Admin page callback: routes between the Settings and Violations tabs.
     */
    public function admin_page() {
        $active_tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'settings'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only tab routing.

        if ($active_tab === 'violations') {
            $this->render_violations_page();
            return;
        }

        $options   = get_option('csp_reporting_options', array());
        $log_stats = $this->logger->get_log_statistics();
        $log_files = $this->logger->get_log_files();
        $db_stats  = $this->database->get_stats(7);

        include CSP_REPORTING_PLUGIN_DIR . 'templates/admin-page.php';
    }

    /**
     * Render the tab navigation shared by both admin screens.
     *
     * @param string $active
     */
    public function render_tabs( $active ) {
        $tabs = array(
            'settings' => __('Settings', 'csp-reporting'),
            'violations' => __('Violations', 'csp-reporting'),
        );

        echo '<h2 class="nav-tab-wrapper">';
        foreach ($tabs as $slug => $label) {
            printf(
                '<a href="%s" class="nav-tab %s">%s</a>',
                esc_url(add_query_arg(array( 'page' => 'csp-reporting', 'tab' => $slug ), admin_url('options-general.php'))),
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
        if ($list_table->current_action() === 'delete' && ! empty($_REQUEST['violation_ids'])) {
            check_admin_referer('bulk-csp_violations');

            if (current_user_can('manage_options')) {
                $deleted = $this->database->delete_violations( (array) $_REQUEST['violation_ids']);
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
    public function sanitize_options( $input ) {
        // Start from the stored options so keys the form doesn't submit
        // (or that other code manages) survive a save.
        $sanitized = get_option('csp_reporting_options', array());

        $sanitized['csp_enabled'] = ! empty($input['csp_enabled']) ? 1 : 0;

        $valid_modes           = array( CSP_Policy::MODE_REPORT_ONLY, CSP_Policy::MODE_ENFORCE, CSP_Policy::MODE_BOTH );
        $sanitized['csp_mode'] = isset($input['csp_mode']) && in_array($input['csp_mode'], $valid_modes, true)
            ? $input['csp_mode']
            : CSP_Policy::MODE_REPORT_ONLY;

        $sanitized['csp_test_policy'] = isset($input['csp_test_policy']) ? sanitize_textarea_field($input['csp_test_policy']) : '';

        // Policy builder: sanitize each directive's source list. Semicolons
        // and line breaks are stripped so a value cannot inject directives.
        $directives = array();
        if ( ! empty($input['csp_policy_directives']) && is_array($input['csp_policy_directives'])) {
            foreach (CSP_Policy::source_directives() as $directive) {
                if ( ! isset($input['csp_policy_directives'][$directive])) {
                    continue;
                }
                $value = sanitize_text_field($input['csp_policy_directives'][$directive]);
                $value = trim(preg_replace('/[;,]+/', ' ', $value));
                $value = preg_replace('/\s+/', ' ', $value);
                if ($value !== '') {
                    $directives[$directive] = $value;
                }
            }
            foreach (CSP_Policy::flag_directives() as $directive) {
                if ( ! empty($input['csp_policy_directives'][$directive])) {
                    $directives[$directive] = '';
                }
            }
        }
        $sanitized['csp_policy_directives'] = $directives;

        $sanitized['csp_admin_pages']         = ! empty($input['csp_admin_pages']) ? 1 : 0;
        $sanitized['log_retention_days']      = intval($input['log_retention_days']);
        $sanitized['log_max_size']            = intval($input['log_max_size']);
        $sanitized['file_logging_enabled']    = ! empty($input['file_logging_enabled']) ? 1 : 0;
        $sanitized['rate_limit_per_minute']   = isset($input['rate_limit_per_minute']) ? max(0, intval($input['rate_limit_per_minute'])) : CSP_Reporter::RATE_LIMIT_PER_MINUTE;
        $sanitized['enable_admin_notices']    = ! empty($input['enable_admin_notices']) ? 1 : 0;
        $sanitized['purge_logs_on_uninstall'] = ! empty($input['purge_logs_on_uninstall']) ? 1 : 0;

        // One pattern per line; empty lines dropped.
        $patterns                     = isset($input['ignore_patterns']) ? sanitize_textarea_field($input['ignore_patterns']) : '';
        $sanitized['ignore_patterns'] = array_values(array_filter(array_map('trim', preg_split('/[\r\n]+/', $patterns))));

        // Notifications.
        $sanitized['notify_email_enabled']    = ! empty($input['notify_email_enabled']) ? 1 : 0;
        $sanitized['notify_immediate_high']   = ! empty($input['notify_immediate_high']) ? 1 : 0;
        $sanitized['notify_digest_frequency'] = isset($input['notify_digest_frequency']) && $input['notify_digest_frequency'] === 'weekly' ? 'weekly' : 'daily';
        $sanitized['notify_webhook_url']      = isset($input['notify_webhook_url']) ? esc_url_raw(trim($input['notify_webhook_url'])) : '';

        $recipients                           = isset($input['notify_email_recipients']) ? explode(',', $input['notify_email_recipients']) : array();
        $recipients                           = array_filter(array_map('sanitize_email', array_map('trim', $recipients)));
        $sanitized['notify_email_recipients'] = implode(', ', $recipients);

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
        echo '<p>' . esc_html__('Configure your Content Security Policy settings.', 'csp-reporting') . '</p>';
    }

    public function logging_section_callback() {
        echo '<p>' . esc_html__('Configure logging behavior and file management.', 'csp-reporting') . '</p>';
    }

    public function notifications_section_callback() {
        echo '<p>' . esc_html__('Get notified about violation activity by email or a Slack-compatible webhook.', 'csp-reporting') . '</p>';
    }

    public function notify_email_enabled_callback() {
        $options = get_option('csp_reporting_options', array());
        $enabled = ! empty($options['notify_email_enabled']) ? 1 : 0;
        echo '<input type="checkbox" name="csp_reporting_options[notify_email_enabled]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . esc_html__('Send digest emails and (optionally) immediate alerts.', 'csp-reporting') . '</p>';
    }

    public function notify_recipients_callback() {
        $options    = get_option('csp_reporting_options', array());
        $recipients = ! empty($options['notify_email_recipients']) ? $options['notify_email_recipients'] : get_option('admin_email');
        echo '<input type="text" class="regular-text" name="csp_reporting_options[notify_email_recipients]" value="' . esc_attr($recipients) . '" />';
        echo '<p class="description">' . esc_html__('Comma-separated email addresses.', 'csp-reporting') . '</p>';
    }

    public function notify_frequency_callback() {
        $options   = get_option('csp_reporting_options', array());
        $frequency = isset($options['notify_digest_frequency']) && $options['notify_digest_frequency'] === 'weekly' ? 'weekly' : 'daily';
        echo '<select name="csp_reporting_options[notify_digest_frequency]">';
        printf('<option value="daily" %s>%s</option>', selected($frequency, 'daily', false), esc_html__('Daily', 'csp-reporting'));
        printf('<option value="weekly" %s>%s</option>', selected($frequency, 'weekly', false), esc_html__('Weekly (Mondays)', 'csp-reporting'));
        echo '</select>';
        echo '<p class="description">' . esc_html__('Digests are only sent when there was violation activity in the period.', 'csp-reporting') . '</p>';
    }

    public function notify_immediate_callback() {
        $options = get_option('csp_reporting_options', array());
        $enabled = ! empty($options['notify_immediate_high']) ? 1 : 0;
        echo '<input type="checkbox" name="csp_reporting_options[notify_immediate_high]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . esc_html(sprintf(__('Alert as soon as a high-severity violation is recorded (throttled to %d alerts per day).', 'csp-reporting'), CSP_Notifications::MAX_ALERTS_PER_DAY)) . '</p>';
    }

    public function notify_webhook_callback() {
        $options = get_option('csp_reporting_options', array());
        $url     = ! empty($options['notify_webhook_url']) ? $options['notify_webhook_url'] : '';
        echo '<input type="url" class="regular-text code" name="csp_reporting_options[notify_webhook_url]" value="' . esc_attr($url) . '" placeholder="https://hooks.slack.com/services/..." />';
        echo '<p class="description">' . esc_html__('Slack-compatible incoming webhook. Receives the same content as the emails. Leave blank to disable.', 'csp-reporting') . '</p>';
    }

    /**
     * Field callbacks
     */
    public function csp_enabled_callback() {
        $options = get_option('csp_reporting_options', array());
        $enabled = ! empty($options['csp_enabled']) ? 1 : 0;
        echo '<input type="checkbox" name="csp_reporting_options[csp_enabled]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . esc_html__('Enable CSP report-only headers on your site.', 'csp-reporting') . '</p>';
    }

    public function csp_mode_callback() {
        $policy  = new CSP_Policy();
        $mode    = $policy->get_mode();
        $options = get_option('csp_reporting_options', array());

        $modes = array(
            CSP_Policy::MODE_REPORT_ONLY => __('Report-Only — log violations, block nothing (recommended while tuning)', 'csp-reporting'),
            CSP_Policy::MODE_ENFORCE => __('Enforce — block violations and report them', 'csp-reporting'),
            CSP_Policy::MODE_BOTH => __('Enforce + Test — enforce this policy while report-only testing a stricter one', 'csp-reporting'),
        );

        echo '<select name="csp_reporting_options[csp_mode]" id="csp-mode-select">';
        foreach ($modes as $value => $label) {
            printf('<option value="%s" %s>%s</option>', esc_attr($value), selected($mode, $value, false), esc_html($label));
        }
        echo '</select>';

        $test_policy = ! empty($options['csp_test_policy']) ? $options['csp_test_policy'] : '';
        echo $mode === CSP_Policy::MODE_BOTH
            ? '<div id="csp-test-policy-row">'
            : '<div id="csp-test-policy-row" style="display:none;">';
        echo '<p><label for="csp-test-policy">' . esc_html__('Test policy (sent as Report-Only alongside the enforced policy):', 'csp-reporting') . '</label></p>';
        echo '<textarea id="csp-test-policy" name="csp_reporting_options[csp_test_policy]" rows="4" class="large-text code">' . esc_textarea($test_policy) . '</textarea>';
        echo '</div>';
    }

    public function policy_builder_callback() {
        $policy     = new CSP_Policy();
        $directives = $policy->get_directives();
        ?>
        <table class="csp-policy-builder widefat striped" id="csp-policy-builder">
            <thead>
                <tr>
                    <th style="width:180px;"><?php esc_html_e('Directive', 'csp-reporting'); ?></th>
                    <th><?php esc_html_e('Sources (space-separated; blank omits the directive)', 'csp-reporting'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach (CSP_Policy::source_directives() as $directive) : ?>
                <tr>
                    <td><code><?php echo esc_html($directive); ?></code></td>
                    <td>
                        <input type="text"
                                class="large-text code csp-directive-input"
                                data-directive="<?php echo esc_attr($directive); ?>"
                                name="csp_reporting_options[csp_policy_directives][<?php echo esc_attr($directive); ?>]"
                                value="<?php echo esc_attr(isset($directives[$directive]) ? $directives[$directive] : ''); ?>" />
                    </td>
                </tr>
                <?php endforeach; ?>
                <?php foreach (CSP_Policy::flag_directives() as $directive) : ?>
                <tr>
                    <td><code><?php echo esc_html($directive); ?></code></td>
                    <td>
                        <label>
                            <input type="checkbox"
                                    name="csp_reporting_options[csp_policy_directives][<?php echo esc_attr($directive); ?>]"
                                    value="1" <?php checked(isset($directives[$directive])); ?> />
                            <?php esc_html_e('Enabled', 'csp-reporting'); ?>
                        </label>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <p class="csp-policy-presets">
            <strong><?php esc_html_e('Presets:', 'csp-reporting'); ?></strong>
            <button type="button" class="button button-small csp-preset" data-preset="google-fonts"><?php esc_html_e('Google Fonts', 'csp-reporting'); ?></button>
            <button type="button" class="button button-small csp-preset" data-preset="google-analytics"><?php esc_html_e('Google Analytics', 'csp-reporting'); ?></button>
            <button type="button" class="button button-small csp-preset" data-preset="gtm"><?php esc_html_e('Tag Manager', 'csp-reporting'); ?></button>
            <button type="button" class="button button-small csp-preset" data-preset="youtube"><?php esc_html_e('YouTube', 'csp-reporting'); ?></button>
        </p>
        <p class="description">
            <?php esc_html_e('The generated header preview updates as you type.', 'csp-reporting'); ?>
        </p>
        <pre id="csp-policy-preview" class="code" style="white-space:pre-wrap;"></pre>
        <?php
    }

    public function log_retention_callback() {
        $options   = get_option('csp_reporting_options', array());
        $retention = ! empty($options['log_retention_days']) ? intval($options['log_retention_days']) : 30;
        echo '<input type="number" name="csp_reporting_options[log_retention_days]" value="' . esc_attr($retention) . '" min="1" max="365" />';
        echo '<p class="description">' . esc_html__('Number of days to keep log files before automatic cleanup.', 'csp-reporting') . '</p>';
    }

    public function log_max_size_callback() {
        $options  = get_option('csp_reporting_options', array());
        $max_size = ! empty($options['log_max_size']) ? intval($options['log_max_size']) : 10485760;
        echo '<input type="number" name="csp_reporting_options[log_max_size]" value="' . esc_attr($max_size) . '" min="1048576" step="1048576" />';
        echo '<p class="description">' . esc_html__('Maximum size of a single log file in bytes. Files will be rotated when this size is reached.', 'csp-reporting') . '</p>';
    }

    public function admin_notices_callback() {
        $options = get_option('csp_reporting_options', array());
        $enabled = ! empty($options['enable_admin_notices']) ? 1 : 0;
        echo '<input type="checkbox" name="csp_reporting_options[enable_admin_notices]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . esc_html__('Show admin notices for important CSP events.', 'csp-reporting') . '</p>';
    }

    public function file_logging_callback() {
        $options = get_option('csp_reporting_options', array());
        $enabled = ! empty($options['file_logging_enabled']) ? 1 : 0;
        echo '<input type="checkbox" name="csp_reporting_options[file_logging_enabled]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . esc_html__('Also write raw reports to log files in wp-content/csp-reports/. The violations database is the primary store; file logs are for external tooling.', 'csp-reporting') . '</p>';
    }

    public function rate_limit_callback() {
        $options = get_option('csp_reporting_options', array());
        $limit   = isset($options['rate_limit_per_minute']) ? intval($options['rate_limit_per_minute']) : CSP_Reporter::RATE_LIMIT_PER_MINUTE;
        echo '<input type="number" name="csp_reporting_options[rate_limit_per_minute]" value="' . esc_attr($limit) . '" min="0" max="1000" />';
        echo '<p class="description">' . esc_html__('Maximum reports accepted per minute from a single IP. 0 disables the limit.', 'csp-reporting') . '</p>';
    }

    public function ignore_patterns_callback() {
        $patterns = CSP_Utils::get_ignore_patterns();
        echo '<textarea name="csp_reporting_options[ignore_patterns]" rows="6" cols="60" class="large-text code">' . esc_textarea(implode("\n", $patterns)) . '</textarea>';
        echo '<p class="description">' . esc_html__('One pattern per line. Reports whose blocked URI or source file contains a pattern are dropped. Defaults cover browser-extension noise.', 'csp-reporting') . '</p>';
    }

    public function csp_admin_pages_callback() {
        $options = get_option('csp_reporting_options', array());
        $enabled = ! empty($options['csp_admin_pages']) ? 1 : 0;
        echo '<input type="checkbox" name="csp_reporting_options[csp_admin_pages]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . esc_html__('Also send the CSP header on wp-admin pages. Leave disabled unless your policy is known to be admin-safe.', 'csp-reporting') . '</p>';
    }

    public function purge_logs_callback() {
        $options = get_option('csp_reporting_options', array());
        $enabled = ! empty($options['purge_logs_on_uninstall']) ? 1 : 0;
        echo '<input type="checkbox" name="csp_reporting_options[purge_logs_on_uninstall]" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">' . esc_html__('Delete the log directory and all violation data when the plugin is uninstalled.', 'csp-reporting') . '</p>';
    }

    /**
     * Download log file via AJAX
     */
    public function download_log_file() {
        check_ajax_referer('csp_admin_nonce', 'nonce');

        if ( ! current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'csp-reporting'));
        }

        $file_path = sanitize_text_field($_POST['file_path']);

        if ( ! file_exists($file_path) || ! is_readable($file_path)) {
            wp_die(esc_html__('File not found or not readable.', 'csp-reporting'));
        }

        // Verify the file is within the log directory
        $log_dir   = realpath(CSP_REPORTING_LOG_DIR);
        $file_path = realpath($file_path);

        if (strpos($file_path, $log_dir) !== 0) {
            wp_die(esc_html__('Invalid file path.', 'csp-reporting'));
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

        if ( ! current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'csp-reporting'));
        }

        $files         = $this->logger->get_log_files();
        $deleted_count = 0;

        foreach ($files as $file) {
            if (unlink($file)) {
                ++$deleted_count;
            }
        }

        wp_send_json_success(array(
            'message' => sprintf(__('%d log files have been cleared.', 'csp-reporting'), $deleted_count),
        ));
    }

    /**
     * Get log file content via AJAX
     */
    public function get_log_content() {
        check_ajax_referer('csp_admin_nonce', 'nonce');

        if ( ! current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'csp-reporting'));
        }

        $file_path = sanitize_text_field($_POST['file_path']);

        if ( ! file_exists($file_path) || ! is_readable($file_path)) {
            wp_send_json_error(array(
                'message' => __('File not found or not readable.', 'csp-reporting'),
            ));
        }

        // Verify the file is within the log directory
        $log_dir   = realpath(CSP_REPORTING_LOG_DIR);
        $file_path = realpath($file_path);

        if (strpos($file_path, $log_dir) !== 0) {
            wp_send_json_error(array(
                'message' => __('Invalid file path.', 'csp-reporting'),
            ));
        }

        $content = $this->logger->get_log_contents($file_path, 1000); // Limit to 1000 lines

        if ($content === false) {
            wp_send_json_error(array(
                'message' => __('Failed to read file content.', 'csp-reporting'),
            ));
        }

        wp_send_json_success(array(
            'content' => $content,
        ));
    }

    /**
     * One-click "Allow this source": add the blocked origin to the violated
     * directive in the stored policy.
     */
    public function allow_source() {
        check_ajax_referer('csp_admin_nonce', 'nonce');

        if ( ! current_user_can('manage_options')) {
            wp_send_json_error(array(
                'message' => __('You do not have sufficient permissions to do this.', 'csp-reporting'),
            ));
        }

        $id        = isset($_POST['violation_id']) ? intval($_POST['violation_id']) : 0;
        $violation = $this->database->get_violation($id);

        if ( ! $violation) {
            wp_send_json_error(array( 'message' => __('Violation not found.', 'csp-reporting') ));
        }

        $directive = CSP_Policy::base_directive($violation['directive']);
        $source    = CSP_Policy::source_from_blocked_uri($violation['blocked_uri']);

        if ( ! $directive || ! $source) {
            wp_send_json_error(array(
                'message' => __('This violation has no allowable source (inline/eval violations need a policy change, not a new source).', 'csp-reporting'),
            ));
        }

        $policy = new CSP_Policy();

        if ( ! $policy->add_source($directive, $source)) {
            wp_send_json_error(array(
                'message' => sprintf(__('%1$s is already allowed for %2$s.', 'csp-reporting'), $source, $directive),
            ));
        }

        wp_send_json_success(array(
            'message' => sprintf(__('Added %1$s to %2$s. The updated policy is live on the next page load.', 'csp-reporting'), $source, $directive),
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

        if ( ! current_user_can('manage_options')) {
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
     * Show a dismissible notice when new high-severity violations arrived
     * since the user last dismissed it (looking back at most 7 days).
     */
    public function show_admin_notices() {
        if ( ! current_user_can('manage_options')) {
            return;
        }

        $options = get_option('csp_reporting_options', array());

        if (empty($options['enable_admin_notices'])) {
            return;
        }

        $dismissed_at = get_user_meta(get_current_user_id(), 'csp_notice_dismissed_at', true);
        $week_ago     = gmdate('Y-m-d H:i:s', time() - ( 7 * DAY_IN_SECONDS ));
        $since        = ( $dismissed_at && $dismissed_at > $week_ago ) ? $dismissed_at : $week_ago;

        $count = $this->database->count_high_since($since);

        if ($count < 1) {
            return;
        }

        printf(
            '<div class="notice notice-error is-dismissible csp-high-notice"><p>%s <a href="%s">%s</a></p></div>',
            esc_html(sprintf(
                _n(
                    'CSP Reporting: %d new high-severity violation detected.',
                    'CSP Reporting: %d new high-severity violations detected.',
                    $count,
                    'csp-reporting'
                ),
                $count
            )),
            esc_url(admin_url('options-general.php?page=csp-reporting&tab=violations&severity=high')),
            esc_html__('Review violations', 'csp-reporting')
        );

        // Persist dismissal without requiring admin.js on every screen.
        ?>
        <script>
        jQuery(document).on('click', '.csp-high-notice .notice-dismiss', function() {
            jQuery.post(ajaxurl, {
                action: 'csp_dismiss_notice',
                nonce: '<?php echo esc_js(wp_create_nonce('csp_dismiss_notice')); ?>'
            });
        });
        </script>
        <?php
    }

    /**
     * Record when the current user dismissed the high-severity notice.
     */
    public function dismiss_high_severity_notice() {
        check_ajax_referer('csp_dismiss_notice', 'nonce');

        if ( ! current_user_can('manage_options')) {
            wp_send_json_error();
        }

        update_user_meta(get_current_user_id(), 'csp_notice_dismissed_at', current_time('mysql'));

        wp_send_json_success();
    }

    /**
     * Register the at-a-glance dashboard widget.
     */
    public function register_dashboard_widget() {
        if ( ! current_user_can('manage_options')) {
            return;
        }

        wp_add_dashboard_widget(
            'csp_reporting_widget',
            __('CSP Violations', 'csp-reporting'),
            array( $this, 'render_dashboard_widget' )
        );
    }

    /**
     * Render the dashboard widget: 7-day sparkline plus top blocked sources.
     */
    public function render_dashboard_widget() {
        $stats = $this->database->get_stats(7);

        echo '<p>' . esc_html(sprintf(
            /* translators: 1: report count, 2: pattern count */
            __('%1$s reports across %2$s unique patterns in the last 7 days.', 'csp-reporting'),
            number_format_i18n($stats['total_hits']),
            number_format_i18n($stats['unique_patterns'])
        )) . '</p>';

        echo $this->render_sparkline($stats['by_day']); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- SVG built from integers.

        if ( ! empty($stats['top_blocked'])) {
            echo '<h4>' . esc_html__('Top blocked sources', 'csp-reporting') . '</h4><ul>';
            foreach ($stats['top_blocked'] as $row) {
                $uri = $row['blocked_uri'] !== '' ? $row['blocked_uri'] : __('(inline)', 'csp-reporting');
                if (strlen($uri) > 50) {
                    $uri = substr($uri, 0, 47) . '…';
                }
                printf(
                    '<li><code>%s</code> — %s</li>',
                    esc_html($uri),
                    esc_html(number_format_i18n( (int) $row['hits']))
                );
            }
            echo '</ul>';
        }

        printf(
            '<p><a href="%s">%s</a></p>',
            esc_url(admin_url('options-general.php?page=csp-reporting&tab=violations')),
            esc_html__('View all violations →', 'csp-reporting')
        );
    }

    /**
     * Build an inline SVG sparkline from day => count buckets.
     *
     * @param array $by_day
     * @return string
     */
    private function render_sparkline( $by_day ) {
        $values = array_values(array_map('intval', $by_day));
        $count  = count($values);

        if ($count < 2) {
            return '';
        }

        $width  = 280;
        $height = 40;
        $max    = max(1, max($values));

        $points = array();
        foreach ($values as $i => $value) {
            $x        = round($i * ( $width / ( $count - 1 ) ), 1);
            $y        = round($height - ( $value / $max ) * ( $height - 4 ) - 2, 1);
            $points[] = $x . ',' . $y;
        }

        return sprintf(
            '<svg width="%1$d" height="%2$d" viewBox="0 0 %1$d %2$d" role="img" aria-label="%3$s">' .
            '<polyline fill="none" stroke="#2271b1" stroke-width="2" points="%4$s" /></svg>',
            $width,
            $height,
            esc_attr__('Violations per day, last 7 days', 'csp-reporting'),
            esc_attr(implode(' ', $points))
        );
    }

    /**
     * Add the network admin overview page (multisite).
     */
    public function add_network_admin_menu() {
        add_submenu_page(
            'settings.php',
            __('CSP Reporting', 'csp-reporting'),
            __('CSP Reporting', 'csp-reporting'),
            'manage_network',
            'csp-reporting-network',
            array( $this, 'render_network_admin_page' )
        );
    }

    /**
     * Network overview: per-site violation counts for the last 7 days.
     *
     * Policies and violations are per site; this page only aggregates the
     * numbers so a network admin can see which sites need attention.
     */
    public function render_network_admin_page() {
        if ( ! current_user_can('manage_network')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'csp-reporting'));
        }

        global $wpdb;

        $sites = get_sites(array( 'number' => 100 ));

        echo '<div class="wrap"><h1>' . esc_html__('CSP Reporting — Network Overview', 'csp-reporting') . '</h1>';
        echo '<p>' . esc_html__('Violation activity per site over the last 7 days. Policies are managed per site under Settings → CSP Reporting.', 'csp-reporting') . '</p>';
        echo '<table class="widefat striped"><thead><tr>';
        echo '<th>' . esc_html__('Site', 'csp-reporting') . '</th>';
        echo '<th>' . esc_html__('Reports', 'csp-reporting') . '</th>';
        echo '<th>' . esc_html__('Unique Patterns', 'csp-reporting') . '</th>';
        echo '<th>' . esc_html__('High Severity', 'csp-reporting') . '</th>';
        echo '</tr></thead><tbody>';

        foreach ($sites as $site) {
            switch_to_blog($site->blog_id);

            $table = CSP_Database::table_name();
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            $has_table = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) === $table;

            $name       = get_bloginfo('name');
            $admin_link = admin_url('options-general.php?page=csp-reporting&tab=violations');

            if ($has_table) {
                $stats = $this->database->get_stats(7);
                printf(
                    '<tr><td><a href="%s">%s</a></td><td>%s</td><td>%s</td><td>%s</td></tr>',
                    esc_url($admin_link),
                    esc_html($name),
                    esc_html(number_format_i18n($stats['total_hits'])),
                    esc_html(number_format_i18n($stats['unique_patterns'])),
                    esc_html(number_format_i18n($stats['by_severity']['high']))
                );
            } else {
                printf(
                    '<tr><td>%s</td><td colspan="3">%s</td></tr>',
                    esc_html($name),
                    esc_html__('Plugin not active on this site.', 'csp-reporting')
                );
            }

            restore_current_blog();
        }

        echo '</tbody></table></div>';
    }

    /**
     * Export violations matching the current filters as CSV or JSON.
     *
     * Linked from the violations screen via admin-post.php.
     */
    public function export_violations() {
        check_admin_referer('csp_export_violations');

        if ( ! current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to do this.', 'csp-reporting'));
        }

        $format = isset($_GET['format']) && $_GET['format'] === 'json' ? 'json' : 'csv';

        $args = array(
            'per_page' => 10000,
            'paged' => 1,
            'orderby' => 'last_seen',
            'order' => 'DESC',
        );

        if ( ! empty($_GET['severity'])) {
            $args['severity'] = sanitize_key($_GET['severity']);
        }
        if ( ! empty($_GET['directive'])) {
            $args['directive'] = sanitize_text_field(wp_unslash($_GET['directive']));
        }
        if ( ! empty($_GET['s'])) {
            $args['search'] = sanitize_text_field(wp_unslash($_GET['s']));
        }

        $rows     = $this->database->get_violations($args);
        $filename = 'csp-violations-' . current_time('Y-m-d') . '.' . $format;

        nocache_headers();
        header('Content-Disposition: attachment; filename="' . $filename . '"');

        if ($format === 'json') {
            header('Content-Type: application/json; charset=utf-8');
            echo wp_json_encode($rows, JSON_PRETTY_PRINT);
            exit;
        }

        header('Content-Type: text/csv; charset=utf-8');

        $columns = array( 'severity', 'directive', 'blocked_uri', 'document_uri', 'source_file', 'line_number', 'hit_count', 'first_seen', 'last_seen' );

        $output = fopen('php://output', 'w');
        fputcsv($output, $columns);

        foreach ($rows as $row) {
            $line = array();
            foreach ($columns as $column) {
                $value = isset($row[$column]) ? $row[$column] : '';
                // Guard against spreadsheet formula injection.
                if (is_string($value) && $value !== '' && strpbrk($value[0], '=+-@') !== false) {
                    $value = "'" . $value;
                }
                $line[] = $value;
            }
            fputcsv($output, $line);
        }

        fclose($output);
        exit;
    }
}
