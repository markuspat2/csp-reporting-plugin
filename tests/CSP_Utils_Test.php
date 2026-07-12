<?php

use PHPUnit\Framework\TestCase;

class CSP_Utils_Test extends TestCase {

    protected function setUp(): void {
        $GLOBALS['csp_test_options'] = array();
    }

    public function test_matches_ignore_patterns_on_blocked_uri() {
        $report = array(
            'blocked-uri' => 'chrome-extension://abcdef/content.js',
            'source-file' => '',
        );

        $this->assertTrue(CSP_Utils::matches_ignore_patterns($report, CSP_Utils::default_ignore_patterns()));
    }

    public function test_matches_ignore_patterns_on_source_file() {
        $report = array(
            'blocked-uri' => 'https://example.com/x.js',
            'source-file' => 'moz-extension://xyz/injector.js',
        );

        $this->assertTrue(CSP_Utils::matches_ignore_patterns($report, CSP_Utils::default_ignore_patterns()));
    }

    public function test_matches_ignore_patterns_is_case_insensitive() {
        $report = array('blocked-uri' => 'CHROME-EXTENSION://abc/x.js');

        $this->assertTrue(CSP_Utils::matches_ignore_patterns($report, array('chrome-extension://')));
    }

    public function test_real_violations_are_not_ignored() {
        $report = array(
            'blocked-uri' => 'https://evil.example.com/inject.js',
            'source-file' => 'https://example.test/page',
        );

        $this->assertFalse(CSP_Utils::matches_ignore_patterns($report, CSP_Utils::default_ignore_patterns()));
    }

    public function test_get_ignore_patterns_defaults_when_unset() {
        $this->assertSame(CSP_Utils::default_ignore_patterns(), CSP_Utils::get_ignore_patterns());
    }

    public function test_get_ignore_patterns_reads_option_and_splits_strings() {
        $GLOBALS['csp_test_options']['csp_reporting_options'] = array(
            'ignore_patterns' => "foo\nbar\n\n",
        );

        $this->assertSame(array('foo', 'bar'), CSP_Utils::get_ignore_patterns());
    }

    public function test_report_hash_dedup_key_is_stable_and_distinct() {
        $a = CSP_Database::report_hash('script-src', 'https://x.example.com/a.js', 'https://example.test/');
        $b = CSP_Database::report_hash('script-src', 'https://x.example.com/a.js', 'https://example.test/');
        $c = CSP_Database::report_hash('script-src', 'https://x.example.com/b.js', 'https://example.test/');

        $this->assertSame($a, $b);
        $this->assertNotSame($a, $c);
    }
}
