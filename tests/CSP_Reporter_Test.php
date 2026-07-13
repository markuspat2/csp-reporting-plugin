<?php

use PHPUnit\Framework\TestCase;

class CSP_Reporter_Test extends TestCase {

    private $reporter;

    protected function setUp(): void {
        $GLOBALS['csp_test_options'] = array();
        $this->reporter = new CSP_Reporter();
    }

    public function test_validate_report_structure_accepts_minimal_report() {
        $this->assertTrue($this->reporter->validate_report_structure(array(
            'csp-report' => array(
                'document-uri' => 'https://example.test/page',
                'violated-directive' => 'script-src-elem',
            ),
        )));
    }

    public function test_validate_report_structure_rejects_bad_shapes() {
        $this->assertFalse($this->reporter->validate_report_structure(null));
        $this->assertFalse($this->reporter->validate_report_structure(array()));
        $this->assertFalse($this->reporter->validate_report_structure(array('csp-report' => 'nope')));
        $this->assertFalse($this->reporter->validate_report_structure(array(
            'csp-report' => array('document-uri' => 'https://example.test/'),
        )));
    }

    public function test_severity_high_for_dangerous_directives() {
        foreach (array('object-src', 'base-uri', 'form-action', 'frame-ancestors') as $directive) {
            $this->assertSame('high', $this->reporter->assess_violation_severity(array(
                'violated-directive' => $directive,
                'blocked-uri' => 'https://example.com/x',
            )), $directive);
        }
    }

    public function test_severity_high_for_dangerous_schemes_in_script_src() {
        $this->assertSame('high', $this->reporter->assess_violation_severity(array(
            'violated-directive' => 'script-src',
            'blocked-uri' => 'javascript:alert(1)',
        )));
        $this->assertSame('high', $this->reporter->assess_violation_severity(array(
            'violated-directive' => 'script-src-elem',
            'blocked-uri' => 'data:text/javascript,x',
        )));
    }

    public function test_severity_medium_for_inline_and_eval_keywords() {
        // Browsers report blocked inline/eval as "inline"/"eval", not
        // "unsafe-inline"/"unsafe-eval" — the 1.x check could never match.
        $this->assertSame('medium', $this->reporter->assess_violation_severity(array(
            'violated-directive' => 'script-src',
            'blocked-uri' => 'inline',
        )));
        $this->assertSame('medium', $this->reporter->assess_violation_severity(array(
            'violated-directive' => 'script-src',
            'blocked-uri' => 'eval',
        )));
    }

    public function test_severity_low_for_style_violations() {
        $this->assertSame('low', $this->reporter->assess_violation_severity(array(
            'violated-directive' => 'style-src',
            'blocked-uri' => 'https://fonts.googleapis.com/css',
        )));
    }

    public function test_extract_reports_legacy_single_object() {
        $reports = $this->reporter->extract_reports(array(
            'csp-report' => array(
                'document-uri' => 'https://example.test/page',
                'violated-directive' => 'img-src',
            ),
        ));

        $this->assertCount(1, $reports);
    }

    public function test_extract_reports_reporting_api_batch() {
        $reports = $this->reporter->extract_reports(array(
            array(
                'type' => 'csp-violation',
                'url' => 'https://example.test/page',
                'body' => array(
                    'documentURL' => 'https://example.test/page',
                    'effectiveDirective' => 'script-src-elem',
                    'blockedURL' => 'https://evil.example.com/x.js',
                    'disposition' => 'enforce',
                    'statusCode' => 200,
                ),
            ),
            array('type' => 'deprecation', 'body' => array()),
            'garbage',
        ));

        $this->assertCount(1, $reports);
        $this->assertSame('script-src-elem', $reports[0]['csp-report']['violated-directive']);
        $this->assertSame('https://evil.example.com/x.js', $reports[0]['csp-report']['blocked-uri']);
        $this->assertSame('enforce', $reports[0]['csp-report']['disposition']);
    }

    public function test_extract_reports_rejects_invalid_payloads() {
        $this->assertSame(array(), $this->reporter->extract_reports('scalar'));
        $this->assertSame(array(), $this->reporter->extract_reports(array('csp-report' => array())));
        $this->assertSame(array(), $this->reporter->extract_reports(array(array('type' => 'csp-violation', 'body' => array()))));
    }
}
