<?php

use PHPUnit\Framework\TestCase;

/**
 * Database double that records inserts instead of touching $wpdb.
 */
class CSP_Test_Recording_Database extends CSP_Database {

    public $inserted = array();

    public function insert_violation( $violation ) {
        $this->inserted[] = $violation;
        return true;
    }
}

/**
 * Script samples and per-script deduplication for the inline inventory.
 */
class CSP_Inline_Inventory_Test extends TestCase {

    private $database;
    private $reporter;

    protected function setUp(): void {
        $GLOBALS['csp_test_options'] = array();
        $GLOBALS['csp_test_filters'] = array();
        $this->database              = new CSP_Test_Recording_Database();
        $this->reporter              = new CSP_Reporter(null, $this->database);
    }

    public function test_sample_captured_from_legacy_report() {
        $reports = $this->reporter->extract_reports(array(
            'csp-report' => array(
                'document-uri' => 'https://example.test/page',
                'violated-directive' => 'script-src-elem',
                'blocked-uri' => 'inline',
                'source-file' => 'https://example.test/page',
                'line-number' => 42,
                'script-sample' => 'window.dataLayer = window.dataLayer || [',
            ),
        ));

        $this->reporter->process_report($reports[0]);

        $this->assertSame('window.dataLayer = window.dataLayer || [', $this->database->inserted[0]['script_sample']);
        $this->assertSame(42, $this->database->inserted[0]['line_number']);
    }

    public function test_sample_captured_from_reporting_api_body() {
        $reports = $this->reporter->extract_reports(array(
            array(
                'type' => 'csp-violation',
                'url' => 'https://example.test/page',
                'body' => array(
                    'documentURL' => 'https://example.test/page',
                    'effectiveDirective' => 'script-src-attr',
                    'blockedURL' => 'inline',
                    'sourceFile' => 'https://example.test/page',
                    'lineNumber' => 7,
                    'sample' => 'openMenu(event)',
                    'disposition' => 'report',
                ),
            ),
        ));

        $this->assertSame('openMenu(event)', $reports[0]['csp-report']['script-sample']);

        $this->reporter->process_report($reports[0]);

        $this->assertSame('openMenu(event)', $this->database->inserted[0]['script_sample']);
        $this->assertSame('script-src-attr', $this->database->inserted[0]['directive']);
    }

    public function test_missing_or_invalid_sample_is_empty() {
        $this->assertSame('', CSP_Reporter::extract_sample(array()));
        $this->assertSame('', CSP_Reporter::extract_sample(array( 'script-sample' => array( 'x' ) )));
        $this->assertSame('', CSP_Reporter::extract_sample(array( 'script-sample' => '   ' )));
    }

    public function test_sample_is_capped() {
        $long = str_repeat('é', 1000);

        $sample = CSP_Reporter::extract_sample(array( 'script-sample' => $long ));

        $this->assertSame(CSP_Utils::MAX_SAMPLE_LENGTH, mb_strlen($sample, 'UTF-8'));
        $this->assertTrue(mb_check_encoding($sample, 'UTF-8'), 'cap must not split a multibyte character');
    }

    public function test_url_hash_formula_is_unchanged() {
        // Locks the pre-v3 formula so upgrades keep matching existing rows.
        $expected = sha1('script-src-elem|https://cdn.example.com/a.js|https://example.test/page/');

        $this->assertSame($expected, CSP_Database::report_hash('script-src-elem', 'https://cdn.example.com/a.js?ver=1', 'https://example.test/page/?x=1'));
        $this->assertSame(
            $expected,
            CSP_Database::report_hash('script-src-elem', 'https://cdn.example.com/a.js', 'https://example.test/page/', 'https://example.test/other.js', 99, 'ignored'),
            'source location and sample must not affect URL-based hashes'
        );
    }

    public function test_distinct_inline_scripts_on_one_page_get_distinct_hashes() {
        $page = 'https://example.test/page/';

        $by_sample_a = CSP_Database::report_hash('script-src-elem', 'inline', $page, $page, 10, 'var a = 1;');
        $by_sample_b = CSP_Database::report_hash('script-src-elem', 'inline', $page, $page, 20, 'var b = 2;');
        $this->assertNotSame($by_sample_a, $by_sample_b);

        $by_line_a = CSP_Database::report_hash('script-src-elem', 'inline', $page, $page, 10);
        $by_line_b = CSP_Database::report_hash('script-src-elem', 'inline', $page, $page, 20);
        $this->assertNotSame($by_line_a, $by_line_b);

        $eval_a = CSP_Database::report_hash('script-src', 'eval', $page, 'https://example.test/a.js', 5);
        $eval_b = CSP_Database::report_hash('script-src', 'eval', $page, 'https://example.test/b.js', 5);
        $this->assertNotSame($eval_a, $eval_b);
    }

    public function test_same_inline_script_dedupes_when_its_line_shifts() {
        $page = 'https://example.test/page/';

        $this->assertSame(
            CSP_Database::report_hash('script-src-elem', 'inline', $page . '?utm=1', $page . '?utm=1', 10, 'var a = 1;'),
            CSP_Database::report_hash('script-src-elem', 'inline', $page, $page, 37, 'var a = 1;'),
            'with a sample, line shifts and query strings must not split the row'
        );
    }

    public function test_inline_rows_no_longer_collapse_into_the_pre_v3_aggregate() {
        $page = 'https://example.test/page/';

        $this->assertNotSame(
            sha1('script-src-elem|inline|' . $page),
            CSP_Database::report_hash('script-src-elem', 'inline', $page, $page, 10)
        );
    }

    public function test_inline_violation_type() {
        $this->assertSame('script-attr', CSP_Utils::inline_violation_type('script-src-attr', 'inline'));
        $this->assertSame('script-elem', CSP_Utils::inline_violation_type('script-src-elem', 'inline'));
        $this->assertSame('script', CSP_Utils::inline_violation_type("script-src 'self'", 'inline'));
        $this->assertSame('script', CSP_Utils::inline_violation_type('default-src', ''));
        $this->assertSame('eval', CSP_Utils::inline_violation_type('script-src', 'eval'));
        $this->assertSame('style-attr', CSP_Utils::inline_violation_type('style-src-attr', 'inline'));
        $this->assertSame('style-elem', CSP_Utils::inline_violation_type('style-src-elem', 'inline'));
        $this->assertSame('', CSP_Utils::inline_violation_type('script-src-elem', 'https://cdn.example.com/a.js'));
        $this->assertSame('', CSP_Utils::inline_violation_type('img-src', ''));
    }

    public function test_inline_type_labels_distinguish_handlers_from_blocks() {
        $this->assertSame('Inline event handler', CSP_Utils::inline_type_label('script-attr'));
        $this->assertSame('Inline script block', CSP_Utils::inline_type_label('script-elem'));
        $this->assertSame('', CSP_Utils::inline_type_label(''));
    }

    public function test_inline_violations_have_no_allowable_source() {
        // Both the one-click "Allow" action and the By Source bulk allow
        // gate on source_from_blocked_uri().
        foreach (array( 'inline', 'eval', 'wasm-eval', '', 'self' ) as $keyword) {
            $this->assertFalse(CSP_Policy::source_from_blocked_uri($keyword), $keyword);
        }
    }
}
