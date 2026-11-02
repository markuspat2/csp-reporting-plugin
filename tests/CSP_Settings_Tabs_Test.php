<?php

use PHPUnit\Framework\TestCase;

/**
 * Settings are split into tabs; saving one tab must not touch another's
 * fields, and programmatic saves of the whole array must not lose data.
 */
class CSP_Settings_Tabs_Test extends TestCase {

    private $admin;

    protected function setUp(): void {
        $GLOBALS['csp_test_options'] = array(
            'csp_reporting_options' => array(
                'csp_enabled' => 1,
                'csp_mode' => 'both',
                'csp_admin_pages' => 1,
                'csp_policy_directives' => array( 'script-src' => "'self'" ),
                'store_client_ip' => 1,
                'file_logging_enabled' => 1,
                'ignore_patterns' => array( 'chrome-extension://', 'moz-extension://' ),
                'log_max_size' => 10485760,
                'log_retention_days' => 30,
                'notify_email_enabled' => 1,
                'enable_admin_notices' => 1,
            ),
        );
        $this->admin = new CSP_Admin();
    }

    public function test_saving_one_tab_leaves_other_tabs_alone() {
        // The Notifications form posts only its own fields.
        $saved = $this->admin->sanitize_options(array(
            '_tab' => 'notifications',
            'notify_email_enabled' => '',
            'notify_email_recipients' => 'ops@example.test',
        ));

        $this->assertSame(0, $saved['notify_email_enabled']);
        $this->assertSame('ops@example.test', $saved['notify_email_recipients']);
        $this->assertSame(0, $saved['enable_admin_notices'], 'admin notices live on the Notifications tab');

        // General, Policy, and Logging values are untouched.
        $this->assertSame(1, $saved['csp_enabled']);
        $this->assertSame('both', $saved['csp_mode']);
        $this->assertSame(1, $saved['csp_admin_pages']);
        $this->assertSame(array( 'script-src' => "'self'" ), $saved['csp_policy_directives']);
        $this->assertSame(1, $saved['store_client_ip']);
        $this->assertSame(1, $saved['file_logging_enabled']);
        $this->assertSame(array( 'chrome-extension://', 'moz-extension://' ), $saved['ignore_patterns']);
        $this->assertArrayNotHasKey('_tab', $saved);
    }

    public function test_policy_tab_saves_only_directives() {
        $saved = $this->admin->sanitize_options(array(
            '_tab' => 'policy',
            'csp_policy_directives' => array( 'script-src' => "'self' https://cdn.example.com;img-src *" ),
        ));

        $this->assertSame("'self' https://cdn.example.com img-src *", $saved['csp_policy_directives']['script-src']);
        $this->assertSame(1, $saved['csp_enabled']);
        $this->assertSame(1, $saved['notify_email_enabled']);
    }

    public function test_logging_tab_converts_megabytes_and_splits_patterns() {
        $saved = $this->admin->sanitize_options(array(
            '_tab' => 'logging',
            'log_max_size_mb' => '25',
            'log_retention_days' => '14',
            'ignore_patterns' => "chrome-extension://\n\nmy-noise.example\n",
        ));

        $this->assertSame(25 * 1048576, $saved['log_max_size']);
        $this->assertSame(14, $saved['log_retention_days']);
        $this->assertSame(array( 'chrome-extension://', 'my-noise.example' ), $saved['ignore_patterns']);
        $this->assertSame(0, $saved['store_client_ip'], 'unchecked on the submitted tab');
        $this->assertSame('both', $saved['csp_mode']);
    }

    public function test_whole_array_save_keeps_ignore_patterns() {
        // add_source() writes the full stored array back through this
        // sanitizer; ignore_patterns is an array there, not textarea text.
        $stored = $GLOBALS['csp_test_options']['csp_reporting_options'];
        $stored['csp_policy_directives']['img-src'] = 'https://img.example.com';

        $saved = $this->admin->sanitize_options($stored);

        $this->assertSame(array( 'chrome-extension://', 'moz-extension://' ), $saved['ignore_patterns']);
        $this->assertSame('https://img.example.com', $saved['csp_policy_directives']['img-src']);
        $this->assertSame(1, $saved['csp_enabled']);
        $this->assertSame(10485760, $saved['log_max_size']);
    }

    public function test_settings_tabs_and_legacy_slug() {
        $this->assertSame(array( 'general', 'policy', 'logging', 'notifications' ), array_keys(CSP_Admin::settings_tabs()));

        $_GET['tab'] = 'settings'; // Links from before the split.
        $method      = new ReflectionMethod('CSP_Admin', 'current_tab');
        $method->setAccessible(true);
        $this->assertSame('general', $method->invoke($this->admin));

        $_GET['tab'] = 'violations';
        $this->assertSame('violations', $method->invoke($this->admin));
        unset($_GET['tab']);
    }
}
