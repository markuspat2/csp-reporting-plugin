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

    public function test_normalize_uri_strips_query_and_fragment() {
        $this->assertSame(
            'https://s0.wp.com/w.js',
            CSP_Utils::normalize_uri_for_hash('https://s0.wp.com/w.js?ver=202629')
        );
        $this->assertSame(
            'https://example.test/blog/post/',
            CSP_Utils::normalize_uri_for_hash('https://example.test/blog/post/?complianz_scan_token=abc&complianz_id=15327#frag')
        );
        $this->assertSame(
            'https://example.test:8443/x',
            CSP_Utils::normalize_uri_for_hash('HTTPS://Example.Test:8443/x?y=1')
        );
    }

    public function test_normalize_uri_passes_keywords_through() {
        $this->assertSame('inline', CSP_Utils::normalize_uri_for_hash('inline'));
        $this->assertSame('eval', CSP_Utils::normalize_uri_for_hash('eval'));
        $this->assertSame('data', CSP_Utils::normalize_uri_for_hash('data'));
        $this->assertSame('', CSP_Utils::normalize_uri_for_hash(''));
    }

    public function test_report_hash_collapses_scanner_tokens_and_cache_busters() {
        // Same violation observed with a scanner token and a ver cache-buster
        // must dedupe to a single pattern (the bug seen in live testing).
        $a = CSP_Database::report_hash(
            'script-src-elem',
            'https://cdn.userway.org/widget.js',
            'https://example.test/blog/post/?complianz_scan_token=aaa&complianz_id=1'
        );
        $b = CSP_Database::report_hash(
            'script-src-elem',
            'https://cdn.userway.org/widget.js',
            'https://example.test/blog/post/?complianz_scan_token=bbb&complianz_id=2'
        );
        $c = CSP_Database::report_hash(
            'script-src-elem',
            'https://stats.wp.com/w.js?ver=202629',
            'https://example.test/blog/post/'
        );
        $d = CSP_Database::report_hash(
            'script-src-elem',
            'https://stats.wp.com/w.js?ver=202630',
            'https://example.test/blog/post/'
        );

        $this->assertSame($a, $b, 'scanner query tokens must not split patterns');
        $this->assertSame($c, $d, 'ver cache-busters must not split patterns');
        $this->assertNotSame($a, $c);

        // Different page paths remain distinct patterns.
        $e = CSP_Database::report_hash(
            'script-src-elem',
            'https://cdn.userway.org/widget.js',
            'https://example.test/blog/other-post/'
        );
        $this->assertNotSame($a, $e);

        // Inline violations on the same page stay distinct from URL ones.
        $f = CSP_Database::report_hash('script-src', 'inline', 'https://example.test/blog/post/');
        $g = CSP_Database::report_hash('script-src', 'eval', 'https://example.test/blog/post/');
        $this->assertNotSame($f, $g);
    }
}
