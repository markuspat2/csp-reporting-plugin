<?php

use PHPUnit\Framework\TestCase;

/**
 * Request double exposing only what handle_report() reads.
 */
class CSP_Test_Request {
    private $body;

    public function __construct( $body ) {
        $this->body = $body;
    }

    public function get_body() {
        return $this->body;
    }
}

/**
 * Rate limits count reports (not requests) in fixed windows.
 */
class CSP_Rate_Limit_Test extends TestCase {

    private $database;
    private $reporter;

    protected function setUp(): void {
        $GLOBALS['csp_test_options']    = array( 'csp_reporting_options' => array( 'rate_limit_per_minute' => 30 ) );
        $GLOBALS['csp_test_transients'] = array();
        $_SERVER['REMOTE_ADDR']         = '198.51.100.4';
        $this->database                 = new CSP_Test_Recording_Database();
        $this->reporter                 = new CSP_Reporter(null, $this->database);
    }

    private function batch( $count ) {
        $items = array();
        for ($i = 0; $i < $count; $i++) {
            $items[] = array(
                'type' => 'csp-violation',
                'body' => array(
                    'documentURL' => 'https://example.test/p' . $i . '/',
                    'effectiveDirective' => 'img-src',
                    'blockedURL' => 'https://x.example/' . $i . '.png',
                ),
            );
        }
        return new CSP_Test_Request(json_encode($items));
    }

    public function test_one_batch_cannot_exceed_the_per_minute_limit() {
        $response = $this->reporter->handle_report($this->batch(150));

        $this->assertSame(204, $response->status);
        $this->assertCount(30, $this->database->inserted, 'a single request must not insert more than the per-minute limit');

        $response = $this->reporter->handle_report($this->batch(1));
        $this->assertSame(429, $response->status);
        $this->assertCount(30, $this->database->inserted);
    }

    public function test_requests_within_the_limit_are_all_processed() {
        $this->reporter->handle_report($this->batch(10));
        $this->reporter->handle_report($this->batch(20));

        $this->assertCount(30, $this->database->inserted);
    }

    public function test_daily_cap_is_keyed_by_utc_day() {
        $this->reporter->handle_report($this->batch(5));

        // A fixed per-day key means the count resets with the calendar day
        // instead of sliding forward with every report.
        $this->assertSame(5, $GLOBALS['csp_test_transients']['csp_rl_global_' . gmdate('Ymd')]);
    }

    public function test_zero_disables_the_per_minute_limit() {
        $GLOBALS['csp_test_options']['csp_reporting_options']['rate_limit_per_minute'] = 0;

        $this->reporter->handle_report($this->batch(100));

        $this->assertCount(100, $this->database->inserted);
    }

    public function test_invalid_json_is_rejected_without_consuming_allowance() {
        $response = $this->reporter->handle_report(new CSP_Test_Request('{not json'));

        $this->assertSame(400, $response->status);
        $this->assertSame(array(), $GLOBALS['csp_test_transients']);
    }
}
