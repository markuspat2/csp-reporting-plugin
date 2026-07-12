<?php
/**
 * CSP Utils Class
 *
 * Shared helpers used across the plugin.
 */

if (!defined('ABSPATH')) {
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

        foreach ((array) $trusted_headers as $key) {
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
