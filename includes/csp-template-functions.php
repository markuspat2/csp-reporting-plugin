<?php
/**
 * Public template helpers.
 *
 * For themes and other plugins that print their own <script> tags and need
 * them to carry the CSP nonce.
 */

if ( ! defined('ABSPATH')) {
    exit;
}

if ( ! function_exists('csp_nonce')) {
    /**
     * Get the CSP nonce for the current request.
     *
     * Use it to stamp hard-coded script tags that WordPress doesn't print,
     * e.g. a Google Tag Manager snippet in a theme template. Always returns
     * a value, even when nonce mode is off, so templates can stamp
     * unconditionally — an unused nonce attribute is harmless.
     *
     * @return string
     */
    function csp_nonce() {
        return CSP_Nonce::get();
    }
}

if ( ! function_exists('csp_nonce_attr')) {
    /**
     * Get an escaped nonce="…" attribute for the current request.
     *
     *     <script <?php echo csp_nonce_attr(); ?>>…</script>
     *
     * @return string
     */
    function csp_nonce_attr() {
        return 'nonce="' . esc_attr(CSP_Nonce::get()) . '"';
    }
}
