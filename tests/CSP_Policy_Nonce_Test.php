<?php

use PHPUnit\Framework\TestCase;

/**
 * Header output for nonce mode, 'strict-dynamic', and 'report-sample'
 * across the three delivery modes.
 */
class CSP_Policy_Nonce_Test extends TestCase {

    const URL = 'https://example.test/endpoint';

    protected function setUp(): void {
        $GLOBALS['csp_test_options'] = array();
        $GLOBALS['csp_test_filters'] = array();
        $GLOBALS['wp_version']       = '6.6';
        CSP_Nonce::reset();
    }

    private function options( $overrides ) {
        $GLOBALS['csp_test_options']['csp_reporting_options'] = array_merge(
            array(
                'csp_enabled' => true,
                'csp_policy_directives' => array(
                    'default-src' => "'self'",
                    'script-src' => "'self' 'unsafe-inline' https://cdn.example.com",
                    'style-src' => "'self' 'unsafe-inline'",
                ),
                'csp_mode' => 'report-only',
            ),
            $overrides
        );
    }

    private function headers( $allow_nonce = true ) {
        return ( new CSP_Policy() )->get_headers(self::URL, $allow_nonce);
    }

    private function nonce_source() {
        return "'nonce-" . CSP_Nonce::get() . "'";
    }

    /**
     * Extract one directive's source list from a header value.
     */
    private function directive( $header, $name ) {
        foreach (explode(';', $header) as $part) {
            $part = trim($part);
            if (strpos($part . ' ', $name . ' ') === 0) {
                return substr($part, strlen($name) + 1);
            }
        }
        return null;
    }

    public function test_defaults_leave_headers_unchanged() {
        $this->options(array( 'csp_mode' => 'both', 'csp_test_policy' => "script-src 'self'" ));

        $headers = $this->headers();

        $this->assertSame(
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline'; report-uri " . self::URL . '; report-to csp-endpoint',
            $headers['Content-Security-Policy']
        );
        $this->assertSame(
            "script-src 'self'; report-uri " . self::URL . '; report-to csp-endpoint',
            $headers['Content-Security-Policy-Report-Only']
        );
    }

    public function test_report_only_mode_uses_report_only_setting() {
        $this->options(array( 'csp_nonce_report_only' => true ));

        $headers = $this->headers();

        $this->assertSame(
            "'self' 'unsafe-inline' https://cdn.example.com " . $this->nonce_source(),
            $this->directive($headers['Content-Security-Policy-Report-Only'], 'script-src')
        );
    }

    public function test_report_only_mode_ignores_enforce_setting() {
        $this->options(array( 'csp_nonce_enforce' => true ));

        $headers = $this->headers();

        $this->assertStringNotContainsString('nonce-', $headers['Content-Security-Policy-Report-Only']);
        $this->assertFalse(( new CSP_Policy() )->is_nonce_active());
    }

    public function test_enforce_mode_uses_enforce_setting() {
        $this->options(array( 'csp_mode' => 'enforce', 'csp_nonce_enforce' => true ));

        $headers = $this->headers();

        $this->assertStringContainsString($this->nonce_source(), $this->directive($headers['Content-Security-Policy'], 'script-src'));
        $this->assertArrayNotHasKey('Content-Security-Policy-Report-Only', $headers);
    }

    public function test_enforce_mode_ignores_report_only_setting() {
        $this->options(array( 'csp_mode' => 'enforce', 'csp_nonce_report_only' => true ));

        $this->assertStringNotContainsString('nonce-', $this->headers()['Content-Security-Policy']);
        $this->assertFalse(( new CSP_Policy() )->is_nonce_active());
    }

    public function test_both_mode_nonce_on_test_policy_only() {
        $this->options(array(
            'csp_mode' => 'both',
            'csp_test_policy' => "default-src 'self'; script-src 'self' https://cdn.example.com",
            'csp_nonce_report_only' => true,
            'csp_strict_dynamic' => true,
        ));

        $headers = $this->headers();

        // Acceptance check 1: the enforced header is exactly what it was.
        $this->assertSame(
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline'; report-uri " . self::URL . '; report-to csp-endpoint',
            $headers['Content-Security-Policy']
        );

        // Acceptance check 2: the test header carries nonce + strict-dynamic.
        $this->assertSame(
            "'self' https://cdn.example.com " . $this->nonce_source() . " 'strict-dynamic'",
            $this->directive($headers['Content-Security-Policy-Report-Only'], 'script-src')
        );
        $this->assertTrue(( new CSP_Policy() )->is_nonce_active());
    }

    public function test_both_mode_nonce_on_both_headers_uses_same_value() {
        $this->options(array(
            'csp_mode' => 'both',
            'csp_test_policy' => "script-src 'self'",
            'csp_nonce_enforce' => true,
            'csp_nonce_report_only' => true,
        ));

        $headers = $this->headers();

        $this->assertStringContainsString($this->nonce_source(), $headers['Content-Security-Policy']);
        $this->assertStringContainsString($this->nonce_source(), $headers['Content-Security-Policy-Report-Only']);
    }

    public function test_both_mode_without_test_policy_falls_back_to_main_policy_with_nonce() {
        $this->options(array( 'csp_mode' => 'both', 'csp_nonce_report_only' => true ));

        $headers = $this->headers();

        $this->assertStringNotContainsString('nonce-', $headers['Content-Security-Policy']);
        $this->assertSame(
            "'self' 'unsafe-inline' https://cdn.example.com " . $this->nonce_source(),
            $this->directive($headers['Content-Security-Policy-Report-Only'], 'script-src')
        );
    }

    public function test_strict_dynamic_requires_nonce() {
        $this->options(array( 'csp_strict_dynamic' => true ));

        $this->assertStringNotContainsString('strict-dynamic', $this->headers()['Content-Security-Policy-Report-Only']);
    }

    public function test_report_sample_applies_to_every_header_without_nonce() {
        $this->options(array(
            'csp_mode' => 'both',
            'csp_test_policy' => "script-src 'self'",
            'csp_report_sample' => true,
        ));

        $headers = $this->headers();

        $this->assertSame("'self' 'unsafe-inline' https://cdn.example.com 'report-sample'", $this->directive($headers['Content-Security-Policy'], 'script-src'));
        $this->assertSame("'self' 'report-sample'", $this->directive($headers['Content-Security-Policy-Report-Only'], 'script-src'));
    }

    public function test_report_sample_with_nonce_and_strict_dynamic() {
        $this->options(array(
            'csp_nonce_report_only' => true,
            'csp_strict_dynamic' => true,
            'csp_report_sample' => true,
        ));

        $this->assertSame(
            "'self' 'unsafe-inline' https://cdn.example.com " . $this->nonce_source() . " 'strict-dynamic' 'report-sample'",
            $this->directive($this->headers()['Content-Security-Policy-Report-Only'], 'script-src')
        );
    }

    public function test_default_src_fallback_copies_sources_into_new_script_src() {
        $this->options(array(
            'csp_policy_directives' => array(
                'default-src' => "'self' https://cdn.example.com",
                'style-src' => "'self' 'unsafe-inline'",
            ),
            'csp_nonce_report_only' => true,
        ));

        $header = $this->headers()['Content-Security-Policy-Report-Only'];

        // script-src is created right after default-src from a copy of it...
        $this->assertStringStartsWith(
            "default-src 'self' https://cdn.example.com; script-src 'self' https://cdn.example.com " . $this->nonce_source() . ';',
            $header
        );
        // ...and default-src itself (which style-src also falls back to)
        // never gets the nonce.
        $this->assertSame("'self' https://cdn.example.com", $this->directive($header, 'default-src'));
    }

    public function test_no_script_or_default_src_starts_nonce_only_script_src() {
        $this->options(array(
            'csp_policy_directives' => array( 'img-src' => "'self'" ),
            'csp_nonce_report_only' => true,
        ));

        $this->assertSame($this->nonce_source(), $this->directive($this->headers()['Content-Security-Policy-Report-Only'], 'script-src'));
    }

    public function test_report_sample_alone_never_creates_a_script_restriction() {
        $this->options(array(
            'csp_policy_directives' => array( 'img-src' => "'self'" ),
            'csp_report_sample' => true,
        ));

        $this->assertNull($this->directive($this->headers()['Content-Security-Policy-Report-Only'], 'script-src'));
    }

    public function test_script_src_none_is_replaced_not_combined() {
        $this->options(array(
            'csp_policy_directives' => array( 'script-src' => "'none'" ),
            'csp_nonce_report_only' => true,
        ));

        $this->assertSame($this->nonce_source(), $this->directive($this->headers()['Content-Security-Policy-Report-Only'], 'script-src'));
    }

    public function test_sources_already_present_are_not_duplicated() {
        $this->options(array(
            'csp_policy_directives' => array( 'script-src' => "'self' 'Report-Sample'" ),
            'csp_report_sample' => true,
        ));

        $this->assertSame("'self' 'Report-Sample'", $this->directive($this->headers()['Content-Security-Policy-Report-Only'], 'script-src'));
    }

    public function test_nonce_added_after_filter_and_to_script_src_elem() {
        add_filter('csp_policy_directives', function ($directives) {
            $directives['Script-Src']      = "'self'";
            $directives['script-src-elem'] = "'self' https://elem.example.com";
            unset($directives['script-src']);
            return $directives;
        });

        $this->options(array( 'csp_nonce_report_only' => true, 'csp_report_sample' => true ));

        $header = $this->headers()['Content-Security-Policy-Report-Only'];

        $this->assertSame("'self' " . $this->nonce_source() . " 'report-sample'", $this->directive($header, 'script-src'));
        $this->assertSame("'self' https://elem.example.com " . $this->nonce_source() . " 'report-sample'", $this->directive($header, 'script-src-elem'));
    }

    public function test_admin_headers_never_carry_a_nonce() {
        $this->options(array(
            'csp_mode' => 'both',
            'csp_test_policy' => "script-src 'self'",
            'csp_nonce_enforce' => true,
            'csp_nonce_report_only' => true,
            'csp_strict_dynamic' => true,
        ));

        foreach ($this->headers(false) as $value) {
            $this->assertStringNotContainsString('nonce-', $value);
            $this->assertStringNotContainsString('strict-dynamic', $value);
        }
    }

    public function test_nonce_mode_ignored_before_wordpress_6_4() {
        $GLOBALS['wp_version'] = '6.3.2';
        $this->options(array( 'csp_nonce_report_only' => true, 'csp_strict_dynamic' => true, 'csp_report_sample' => true ));

        $header = $this->headers()['Content-Security-Policy-Report-Only'];

        $this->assertStringNotContainsString('nonce-', $header);
        $this->assertStringNotContainsString('strict-dynamic', $header);
        $this->assertStringContainsString("'report-sample'", $header, 'report-sample does not depend on the WordPress version');
        $this->assertFalse(( new CSP_Policy() )->is_nonce_active());
    }

    public function test_nonce_inactive_when_plugin_disabled() {
        $this->options(array( 'csp_enabled' => false, 'csp_nonce_report_only' => true ));

        $this->assertFalse(( new CSP_Policy() )->is_nonce_active());
    }

    public function test_test_policy_goes_through_normalization() {
        add_filter('csp_policy_directives', function ($directives, $context) {
            if ($context === 'report-only') {
                $directives['IMG-SRC'] = "  'self'    data: ";
            }
            return $directives;
        });

        $this->options(array( 'csp_mode' => 'both', 'csp_test_policy' => "script-src 'self'" ));

        $this->assertStringStartsWith("script-src 'self'; img-src 'self' data:;", $this->headers()['Content-Security-Policy-Report-Only']);
    }
}
