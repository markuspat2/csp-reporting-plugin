<?php

use PHPUnit\Framework\TestCase;

class CSP_Nonce_Test extends TestCase {

    protected function setUp(): void {
        $GLOBALS['csp_test_options'] = array();
        $GLOBALS['csp_test_filters'] = array();
        $GLOBALS['wp_version']       = '6.6';
        CSP_Nonce::reset();
    }

    public function test_nonce_is_base64_of_16_random_bytes() {
        $nonce = CSP_Nonce::get();

        $this->assertMatchesRegularExpression('#^[A-Za-z0-9+/]{22}==$#', $nonce);
        $this->assertSame(16, strlen(base64_decode($nonce, true)));
        $this->assertTrue(CSP_Nonce::is_valid($nonce));
    }

    public function test_nonce_is_stable_within_a_request() {
        $first = CSP_Nonce::get();

        $this->assertSame($first, CSP_Nonce::get());
        $this->assertSame($first, csp_nonce());
    }

    public function test_reset_generates_a_fresh_nonce() {
        $first = CSP_Nonce::get();
        CSP_Nonce::reset();

        $this->assertNotSame($first, CSP_Nonce::get());
    }

    public function test_filter_overrides_the_nonce() {
        add_filter('csp_reporting_nonce', function () {
            return 'EDGE_PLACEHOLDER_NONCE';
        });

        $this->assertSame('EDGE_PLACEHOLDER_NONCE', CSP_Nonce::get());
    }

    public function test_filter_runs_once_per_request() {
        $calls = 0;
        add_filter('csp_reporting_nonce', function ($nonce) use (&$calls) {
            ++$calls;
            return $nonce;
        });

        CSP_Nonce::get();
        CSP_Nonce::get();

        $this->assertSame(1, $calls);
    }

    public function test_invalid_override_falls_back_to_generated_nonce() {
        foreach (array('', 'has space', "quote'", 'semi;colon', array('x'), str_repeat('a', 300)) as $bad) {
            CSP_Nonce::reset();
            $GLOBALS['csp_test_filters'] = array();
            add_filter('csp_reporting_nonce', function () use ($bad) {
                return $bad;
            });

            $nonce = CSP_Nonce::get();

            $this->assertNotSame($bad, $nonce);
            $this->assertMatchesRegularExpression('#^[A-Za-z0-9+/]{22}==$#', $nonce);
        }
    }

    public function test_is_valid_accepts_base64_and_base64url() {
        $this->assertTrue(CSP_Nonce::is_valid('abc+/DEF=='));
        $this->assertTrue(CSP_Nonce::is_valid('abc-_DEF'));
        $this->assertFalse(CSP_Nonce::is_valid('abc==='));
        $this->assertFalse(CSP_Nonce::is_valid('a=b'));
    }

    public function test_nonce_attr_is_escaped_attribute() {
        $this->assertSame('nonce="' . CSP_Nonce::get() . '"', csp_nonce_attr());
    }

    public function test_add_to_attributes_adds_nonce_without_overwriting() {
        $attributes = CSP_Nonce::add_to_attributes(array('src' => 'https://example.test/a.js', 'id' => 'a-js'));
        $this->assertSame(CSP_Nonce::get(), $attributes['nonce']);
        $this->assertSame('a-js', $attributes['id']);

        $existing = CSP_Nonce::add_to_attributes(array('nonce' => 'theirs'));
        $this->assertSame('theirs', $existing['nonce']);
    }

    public function test_is_supported_requires_wordpress_6_4() {
        foreach (array('5.9' => false, '6.3.5' => false, '6.4-RC1' => true, '6.4' => true, '6.8.2' => true) as $version => $expected) {
            $GLOBALS['wp_version'] = $version;
            $this->assertSame($expected, CSP_Nonce::is_supported(), $version);
        }
    }
}
