<?php

use PHPUnit\Framework\TestCase;

class CSP_Policy_Test extends TestCase {

    protected function setUp(): void {
        $GLOBALS['csp_test_options'] = array();
    }

    public function test_parse_policy_text_extracts_directives() {
        $parsed = CSP_Policy::parse_policy_text(
            "default-src 'self'; script-src 'self' https://cdn.example.com; upgrade-insecure-requests;"
        );

        $this->assertSame("'self'", $parsed['default-src']);
        $this->assertSame("'self' https://cdn.example.com", $parsed['script-src']);
        $this->assertArrayHasKey('upgrade-insecure-requests', $parsed);
        $this->assertSame('', $parsed['upgrade-insecure-requests']);
    }

    public function test_parse_policy_text_drops_reporting_and_unknown_directives() {
        $parsed = CSP_Policy::parse_policy_text(
            "script-src 'self'; report-uri https://old.example.com; bogus-src foo;"
        );

        $this->assertSame(array('script-src' => "'self'"), $parsed);
    }

    public function test_build_policy_string_falls_back_to_legacy_text() {
        $GLOBALS['csp_test_options']['csp_reporting_options'] = array(
            'csp_policy' => "img-src 'self' data:; script-src 'self';",
        );

        $policy = new CSP_Policy();

        $this->assertSame("img-src 'self' data:; script-src 'self'", $policy->build_policy_string());
    }

    public function test_get_headers_report_only_mode() {
        $GLOBALS['csp_test_options']['csp_reporting_options'] = array(
            'csp_policy_directives' => array('script-src' => "'self'"),
            'csp_mode' => 'report-only',
        );

        $headers = (new CSP_Policy())->get_headers('https://example.test/endpoint');

        $this->assertArrayHasKey('Content-Security-Policy-Report-Only', $headers);
        $this->assertArrayNotHasKey('Content-Security-Policy', $headers);
        $this->assertArrayHasKey('Reporting-Endpoints', $headers);
        $this->assertStringContainsString('report-uri https://example.test/endpoint', $headers['Content-Security-Policy-Report-Only']);
        $this->assertStringContainsString('report-to csp-endpoint', $headers['Content-Security-Policy-Report-Only']);
        $this->assertSame('csp-endpoint="https://example.test/endpoint"', $headers['Reporting-Endpoints']);
    }

    public function test_get_headers_both_mode_uses_test_policy_for_report_only() {
        $GLOBALS['csp_test_options']['csp_reporting_options'] = array(
            'csp_policy_directives' => array('script-src' => "'self' 'unsafe-inline'"),
            'csp_mode' => 'both',
            'csp_test_policy' => "script-src 'self'",
        );

        $headers = (new CSP_Policy())->get_headers('https://example.test/endpoint');

        $this->assertStringStartsWith("script-src 'self' 'unsafe-inline';", $headers['Content-Security-Policy']);
        $this->assertStringStartsWith("script-src 'self';", $headers['Content-Security-Policy-Report-Only']);
    }

    public function test_base_directive_maps_granular_directives() {
        $this->assertSame('script-src', CSP_Policy::base_directive('script-src-elem'));
        $this->assertSame('style-src', CSP_Policy::base_directive('style-src-attr'));
        $this->assertSame('img-src', CSP_Policy::base_directive('img-src'));
        $this->assertFalse(CSP_Policy::base_directive('sandbox'));
    }

    public function test_source_from_blocked_uri() {
        $this->assertSame('https://cdn.example.com', CSP_Policy::source_from_blocked_uri('https://cdn.example.com/lib.js?v=2'));
        $this->assertSame('https://cdn.example.com:8443', CSP_Policy::source_from_blocked_uri('https://cdn.example.com:8443/x'));
        $this->assertFalse(CSP_Policy::source_from_blocked_uri('inline'));
        $this->assertFalse(CSP_Policy::source_from_blocked_uri('eval'));
        $this->assertFalse(CSP_Policy::source_from_blocked_uri('data:text/html,x'));
        $this->assertFalse(CSP_Policy::source_from_blocked_uri('javascript:alert(1)'));
    }

    public function test_is_source_allowed_matches_origin_host_and_fallback() {
        $GLOBALS['csp_test_options']['csp_reporting_options'] = array(
            'csp_policy_directives' => array(
                'default-src' => "'self' https://fallback.example.com",
                'script-src' => "'self' https://cdn.example.com *.ignored.example",
                'img-src' => 'images.example.com',
            ),
        );

        $policy = new CSP_Policy();

        // Exact origin on the base directive, via a granular directive name.
        $this->assertTrue($policy->is_source_allowed('script-src-elem', 'https://cdn.example.com'));
        $this->assertFalse($policy->is_source_allowed('script-src-elem', 'https://other.example.com'));

        // Bare-host source expressions match the origin's host.
        $this->assertTrue($policy->is_source_allowed('img-src', 'https://images.example.com'));

        // Directive not set falls back to default-src.
        $this->assertTrue($policy->is_source_allowed('connect-src', 'https://fallback.example.com'));
        $this->assertFalse($policy->is_source_allowed('connect-src', 'https://cdn.example.com'));

        // Unknown directives and empty origins are never allowed.
        $this->assertFalse($policy->is_source_allowed('sandbox', 'https://cdn.example.com'));
        $this->assertFalse($policy->is_source_allowed('script-src', ''));
    }

    public function test_add_source_appends_and_deduplicates() {
        $GLOBALS['csp_test_options']['csp_reporting_options'] = array(
            'csp_policy_directives' => array('script-src' => "'self'"),
        );

        $policy = new CSP_Policy();

        $this->assertTrue($policy->add_source('script-src', 'https://cdn.example.com'));
        $this->assertFalse($policy->add_source('script-src', 'https://cdn.example.com'), 'duplicate source must be rejected');

        $saved = $GLOBALS['csp_test_options']['csp_reporting_options']['csp_policy_directives'];
        $this->assertSame("'self' https://cdn.example.com", $saved['script-src']);
    }
}
