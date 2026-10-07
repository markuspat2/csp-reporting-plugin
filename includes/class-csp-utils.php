<?php
/**
 * CSP Utils Class
 *
 * Shared helpers used across the plugin.
 */

if ( ! defined('ABSPATH')) {
    exit;
}

class CSP_Utils {

    /**
     * Get the URL of the violation report endpoint.
     *
     * @return string
     */
    public static function get_report_endpoint_url() {
        return rest_url('csp-reporting/v1/report');
    }

    /**
     * Normalize a URI for deduplication hashing.
     *
     * Query strings and fragments are dropped so cache-busters (?ver=) and
     * per-request tokens (scanner tokens, session ids) don't split one
     * violation pattern into many rows. Keyword pseudo-URIs (inline, eval,
     * data, blob, ...) pass through lowercased.
     *
     * @param string $uri
     * @return string
     */
    public static function normalize_uri_for_hash( $uri ) {
        $uri = trim( (string) $uri);

        if ($uri === '' || strpos($uri, '://') === false) {
            return strtolower($uri);
        }

        $parts = wp_parse_url($uri);

        if (empty($parts['scheme']) || empty($parts['host'])) {
            return strtolower($uri);
        }

        $normalized = strtolower($parts['scheme']) . '://' . strtolower($parts['host']);

        if ( ! empty($parts['port'])) {
            $normalized .= ':' . (int) $parts['port'];
        }

        if ( ! empty($parts['path'])) {
            $normalized .= $parts['path'];
        }

        return $normalized;
    }

    /**
     * Maximum stored length of a violation's code sample. Browsers send at
     * most 40 characters; the cap guards against forged reports.
     */
    const MAX_SAMPLE_LENGTH = 255;

    /**
     * Check whether a blocked-uri is a keyword for inline code or eval
     * rather than a URL.
     *
     * 'inline' and 'eval' are what current browsers send; older Firefox
     * sent 'self' for inline code, and some engines send an empty value.
     *
     * @param string $blocked_uri
     * @return bool
     */
    public static function is_inline_like_uri( $blocked_uri ) {
        return in_array(strtolower(trim( (string) $blocked_uri)), array( '', 'inline', 'eval', 'wasm-eval', 'self' ), true);
    }

    /**
     * Classify an inline-code violation for display.
     *
     * Event handlers (script-src-attr) cannot carry a nonce and need a code
     * change; inline blocks (script-src-elem) can be fixed with a nonce.
     * Reports that only name script-src (older browsers) can't be told
     * apart.
     *
     * @param string $directive Violated directive as stored.
     * @param string $blocked_uri
     * @return string One of script-attr, script-elem, script, eval,
     *                style-attr, style-elem, style; '' for URL-based or
     *                other-directive violations.
     */
    public static function inline_violation_type( $directive, $blocked_uri ) {
        if ( ! self::is_inline_like_uri($blocked_uri)) {
            return '';
        }

        $name = strtolower(trim(explode(' ', trim( (string) $directive))[0]));
        $base = preg_replace('/-(elem|attr)$/', '', $name);

        if ($base === 'default-src') {
            $base = 'script-src';
        }

        if ( ! in_array($base, array( 'script-src', 'style-src' ), true)) {
            return '';
        }

        $kind = $base === 'style-src' ? 'style' : 'script';

        if ($kind === 'script' && in_array(strtolower(trim( (string) $blocked_uri)), array( 'eval', 'wasm-eval' ), true)) {
            return 'eval';
        }

        if (substr($name, -5) === '-attr') {
            return $kind . '-attr';
        }

        if (substr($name, -5) === '-elem') {
            return $kind . '-elem';
        }

        return $kind;
    }

    /**
     * Clean a reported code sample for storage.
     *
     * @param mixed $sample
     * @return string Trimmed and capped at MAX_SAMPLE_LENGTH characters;
     *                '' when absent or not a string.
     */
    public static function sanitize_sample( $sample ) {
        if ( ! is_string($sample)) {
            return '';
        }

        $sample = trim($sample);

        if (function_exists('mb_substr')) {
            return mb_substr($sample, 0, self::MAX_SAMPLE_LENGTH, 'UTF-8');
        }

        return substr($sample, 0, self::MAX_SAMPLE_LENGTH);
    }

    /**
     * Default ignore patterns for noise every site sees: browser extensions,
     * translation proxies, and inert about: pages.
     *
     * @return string[]
     */
    public static function default_ignore_patterns() {
        return array(
            'chrome-extension://',
            'moz-extension://',
            'safari-extension://',
            'safari-web-extension://',
            'ms-browser-extension://',
            'about:blank',
            'about:srcdoc',
            'translate.googleapis.com',
        );
    }

    /**
     * Check whether a violation matches any ignore pattern.
     *
     * Patterns are case-insensitive substrings matched against the blocked
     * URI and the source file.
     *
     * @param array $csp_report The csp-report payload.
     * @param string[] $patterns
     * @return bool
     */
    public static function matches_ignore_patterns( $csp_report, $patterns ) {
        $haystacks = array();

        foreach (array( 'blocked-uri', 'source-file' ) as $field) {
            if ( ! empty($csp_report[$field]) && is_string($csp_report[$field])) {
                $haystacks[] = strtolower($csp_report[$field]);
            }
        }

        foreach ( (array) $patterns as $pattern) {
            $pattern = strtolower(trim($pattern));
            if ($pattern === '') {
                continue;
            }

            foreach ($haystacks as $haystack) {
                if (strpos($haystack, $pattern) !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get the configured ignore patterns.
     *
     * @return string[]
     */
    public static function get_ignore_patterns() {
        $options = get_option('csp_reporting_options', array());

        if ( ! array_key_exists('ignore_patterns', $options)) {
            $patterns = self::default_ignore_patterns();
        } else {
            $patterns = $options['ignore_patterns'];
            if (is_string($patterns)) {
                $patterns = preg_split('/[\r\n]+/', $patterns);
            }
        }

        /**
         * Filter the violation ignore patterns.
         *
         * @param string[] $patterns Case-insensitive substrings matched
         *                           against blocked-uri and source-file.
         */
        return apply_filters('csp_reporting_ignore_patterns', array_values(array_filter( (array) $patterns)));
    }

    /**
     * Get the client IP address.
     *
     * Only REMOTE_ADDR is trusted by default because every other header
     * (X-Forwarded-For, CF-Connecting-IP, ...) is client-controlled unless a
     * proxy in front of the site sets it. Sites behind a trusted proxy can
     * opt in to specific headers:
     *
     *     add_filter('csp_reporting_trusted_ip_headers', function () {
     *         return array('HTTP_CF_CONNECTING_IP');
     *     });
     *
     * @return string
     */
    public static function get_client_ip() {
        /**
         * Filter the list of $_SERVER keys that may carry the real client IP.
         *
         * @param string[] $headers Header keys checked before REMOTE_ADDR.
         */
        $trusted_headers = apply_filters('csp_reporting_trusted_ip_headers', array());

        foreach ( (array) $trusted_headers as $key) {
            if (empty($_SERVER[$key])) {
                continue;
            }

            $ip = $_SERVER[$key];

            // X-Forwarded-For can be a list; the left-most entry is the client.
            if (strpos($ip, ',') !== false) {
                $ip = explode(',', $ip)[0];
            }

            $ip = trim($ip);

            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'Unknown';
    }
}
