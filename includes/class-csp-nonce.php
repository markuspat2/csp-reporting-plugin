<?php
/**
 * CSP Nonce Class
 *
 * One cryptographically random nonce per request for script-src "nonce
 * mode", plus the attribute helper used to stamp it onto script tags.
 *
 * Kept free of WordPress calls (apart from the guarded override filter) so
 * it is unit testable without a WordPress install.
 */

if ( ! defined('ABSPATH')) {
    exit;
}

class CSP_Nonce {

    /**
     * First WordPress release that prints every WP_Scripts tag (enqueued
     * src, inline before/after, wp_localize_script data, translations)
     * through the wp_script_attributes / wp_inline_script_attributes
     * filters. Earlier releases build some of those tags as raw strings, so
     * nonce mode would leave them unstamped and an enforced policy would
     * block them.
     */
    const MIN_WP_VERSION = '6.4';

    /**
     * Random bytes per nonce (128 bits, as the CSP spec recommends).
     */
    const RANDOM_BYTES = 16;

    /**
     * Upper bound on an overridden nonce's length.
     */
    const MAX_LENGTH = 256;

    /**
     * The nonce for the current request, generated on first use.
     *
     * @var string|null
     */
    private static $nonce = null;

    /**
     * Get the nonce for the current request.
     *
     * Generated lazily on first call and returned unchanged for the rest of
     * the request, so the header and every stamped tag carry the same value.
     *
     * @return string Base64 nonce value (without the 'nonce-' prefix).
     */
    public static function get() {
        if (null === self::$nonce) {
            $generated = base64_encode(random_bytes(self::RANDOM_BYTES)); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- CSP nonces are base64 by spec.
            $nonce     = $generated;

            if (function_exists('apply_filters')) {
                /**
                 * Filter the per-request CSP nonce.
                 *
                 * For edge setups that substitute their own value, e.g. a CDN
                 * worker that swaps a fixed placeholder for a fresh nonce on
                 * every response. Values that are not valid CSP base64 or
                 * base64url are ignored and the generated nonce is used.
                 *
                 * @param string $nonce Generated nonce.
                 */
                $nonce = apply_filters('csp_reporting_nonce', $generated);
            }

            self::$nonce = self::is_valid($nonce) ? $nonce : $generated;
        }

        return self::$nonce;
    }

    /**
     * Check a value against the CSP nonce grammar (base64 or base64url).
     *
     * @param mixed $nonce
     * @return bool
     */
    public static function is_valid( $nonce ) {
        return is_string($nonce)
            && strlen($nonce) <= self::MAX_LENGTH
            && (bool) preg_match('#^[A-Za-z0-9+/_-]+={0,2}$#', $nonce);
    }

    /**
     * Forget the current nonce so the next get() generates a new one.
     *
     * Requests never need this; it exists for tests and long-running
     * processes that serve several logical requests.
     */
    public static function reset() {
        self::$nonce = null;
    }

    /**
     * Check whether the running WordPress version supports nonce mode.
     *
     * @return bool
     */
    public static function is_supported() {
        $version = isset($GLOBALS['wp_version']) ? (string) $GLOBALS['wp_version'] : '0';

        // Treat pre-releases (6.4-RC1) as their release version.
        $version = preg_replace('/-.*$/', '', $version);

        return version_compare($version, self::MIN_WP_VERSION, '>=');
    }

    /**
     * Add the nonce to a script tag's attribute array.
     *
     * Callback for wp_script_attributes and wp_inline_script_attributes. An
     * existing nonce attribute (set by the caller or another plugin) is left
     * alone rather than overwritten.
     *
     * @param array $attributes
     * @return array
     */
    public static function add_to_attributes( $attributes ) {
        if ( ! is_array($attributes) || isset($attributes['nonce'])) {
            return $attributes;
        }

        $attributes['nonce'] = self::get();

        return $attributes;
    }
}
