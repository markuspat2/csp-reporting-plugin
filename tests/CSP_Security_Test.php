<?php

use PHPUnit\Framework\TestCase;

/**
 * Regressions for report-derived data reaching the policy, the admin UI,
 * and storage.
 */
class CSP_Security_Test extends TestCase {

    protected function setUp(): void {
        $GLOBALS['csp_test_options'] = array();
    }

    public function test_crafted_hosts_are_not_allowable_origins() {
        $crafted = array(
            "https://cdn.example.com 'unsafe-inline'/lib.js",
            'https://cdn.example.com */x.js',
            'https://a;script-src *x/',
            'https://x<img src=x onerror=alert(1)>.com/a.js',
            "https://evil.com'unsafe-eval'/x.js",
            'https://a.com,b.com/x.js',
        );

        foreach ($crafted as $blocked_uri) {
            $this->assertFalse(CSP_Policy::source_from_blocked_uri($blocked_uri), $blocked_uri);
        }
    }

    public function test_real_origins_still_extracted() {
        $this->assertSame('https://cdn.example.com', CSP_Policy::source_from_blocked_uri('https://CDN.Example.com/lib.js?v=1'));
        $this->assertSame('https://xn--bcher-kva.example', CSP_Policy::source_from_blocked_uri('https://xn--bcher-kva.example/a.js'));
        $this->assertSame('wss://socket.example.com:8443', CSP_Policy::source_from_blocked_uri('wss://socket.example.com:8443/ws'));
        $this->assertSame('http://192.0.2.10', CSP_Policy::source_from_blocked_uri('http://192.0.2.10/x.js'));
        $this->assertSame('https://[2001:db8::1]', CSP_Policy::source_from_blocked_uri('https://[2001:db8::1]/x.js'));
    }

    public function test_add_source_rejects_anything_but_an_origin() {
        $GLOBALS['csp_test_options']['csp_reporting_options'] = array(
            'csp_policy_directives' => array( 'script-src' => "'self'" ),
        );

        $policy = new CSP_Policy();

        foreach (array( "https://cdn.example.com 'unsafe-inline'", '*', "'unsafe-eval'", 'https://a;script-src *', '' ) as $source) {
            $this->assertFalse($policy->add_source('script-src', $source), $source);
        }

        $this->assertSame("'self'", $GLOBALS['csp_test_options']['csp_reporting_options']['csp_policy_directives']['script-src']);
        $this->assertTrue($policy->add_source('script-src', 'https://cdn.example.com'));
    }

    public function test_non_string_report_fields_are_coerced_not_fatal() {
        $reporter = new CSP_Reporter();

        $reports = $reporter->extract_reports(array(
            'csp-report' => array(
                'document-uri' => 'https://example.test/',
                'violated-directive' => 'script-src',
                'blocked-uri' => array( 'x' ),
                'source-file' => array( 'a' => 1 ),
                'disposition' => array( 'enforce' ),
                'line-number' => array( 3 ),
                'column-number' => '7',
            ),
        ));

        $report = $reports[0]['csp-report'];
        $this->assertArrayNotHasKey('blocked-uri', $report);
        $this->assertArrayNotHasKey('source-file', $report);
        $this->assertArrayNotHasKey('disposition', $report);
        $this->assertSame(0, $report['line-number']);
        $this->assertSame(7, $report['column-number']);

        // The severity check used to fatal on an array blocked-uri.
        $this->assertSame('medium', $reporter->assess_violation_severity($report));
    }

    public function test_non_string_reporting_api_fields_are_coerced() {
        $reporter = new CSP_Reporter();

        $reports = $reporter->extract_reports(array(
            array(
                'type' => 'csp-violation',
                'body' => array(
                    'documentURL' => 'https://example.test/',
                    'effectiveDirective' => 'img-src',
                    'blockedURL' => array( 'x' => 1 ),
                    'lineNumber' => 'NaN',
                ),
            ),
        ));

        $this->assertArrayNotHasKey('blocked-uri', $reports[0]['csp-report']);
        $this->assertSame(0, $reports[0]['csp-report']['line-number']);
    }

    public function test_non_string_required_fields_still_reject_the_report() {
        $reporter = new CSP_Reporter();

        $this->assertSame(array(), $reporter->extract_reports(array(
            'csp-report' => array(
                'document-uri' => array( 'https://example.test/' ),
                'violated-directive' => 'img-src',
            ),
        )));
    }

    public function test_file_log_omits_ip_unless_storing_ips_is_enabled() {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.7';
        $logger = new CSP_Logger();
        $report = array(
            'csp-report' => array(
                'document-uri' => 'https://example.test/',
                'violated-directive' => 'img-src',
            ),
        );

        foreach ($logger->get_log_files() as $file) {
            unlink($file);
        }

        $logger->log_violation($report);
        $GLOBALS['csp_test_options']['csp_reporting_options'] = array( 'store_client_ip' => true );
        $logger->log_violation($report);

        $entries = $logger->read_log_entries($logger->get_log_files()[0]);

        $this->assertSame('', $entries[0]['ip_address']);
        $this->assertSame('203.0.113.7', $entries[1]['ip_address']);
    }
}
