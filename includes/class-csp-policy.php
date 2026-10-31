<?php
/**
 * CSP Policy Class
 *
 * Structured model of the Content Security Policy: directive => sources.
 * Handles parsing legacy free-text policies, building header values, and
 * policy mutations like "allow this source".
 */

if ( ! defined('ABSPATH')) {
    exit;
}

class CSP_Policy {

    const MODE_REPORT_ONLY = 'report-only';
    const MODE_ENFORCE     = 'enforce';
    const MODE_BOTH        = 'both';

    /**
     * Directives that take a source list.
     *
     * @return string[]
     */
    public static function source_directives() {
        return array(
            'default-src',
            'script-src',
            'style-src',
            'img-src',
            'font-src',
            'connect-src',
            'frame-src',
            'media-src',
            'object-src',
            'worker-src',
            'manifest-src',
            'child-src',
            'form-action',
            'frame-ancestors',
            'base-uri',
        );
    }

    /**
     * Valueless directives.
     *
     * @return string[]
     */
    public static function flag_directives() {
        return array(
            'upgrade-insecure-requests',
            'block-all-mixed-content',
        );
    }

    /**
     * Get the configured directives as an array of directive => source string.
     *
     * Prefers the structured option; falls back to parsing the legacy
     * free-text csp_policy so 1.x settings keep working untouched.
     *
     * @return array
     */
    public function get_directives() {
        $options = get_option('csp_reporting_options', array());

        if ( ! empty($options['csp_policy_directives']) && is_array($options['csp_policy_directives'])) {
            return $options['csp_policy_directives'];
        }

        $legacy = ! empty($options['csp_policy']) ? $options['csp_policy'] : '';

        return self::parse_policy_text($legacy);
    }

    /**
     * Get the delivery mode.
     *
     * @return string One of the MODE_* constants.
     */
    public function get_mode() {
        $options = get_option('csp_reporting_options', array());
        $mode    = isset($options['csp_mode']) ? $options['csp_mode'] : self::MODE_REPORT_ONLY;

        $valid = array( self::MODE_REPORT_ONLY, self::MODE_ENFORCE, self::MODE_BOTH );

        return in_array($mode, $valid, true) ? $mode : self::MODE_REPORT_ONLY;
    }

    /**
     * Parse a free-text policy into directive => sources.
     *
     * @param string $text
     * @return array
     */
    public static function parse_policy_text( $text ) {
        $directives = array();

        foreach (explode(';', (string) $text) as $part) {
            $part = trim(preg_replace('/\s+/', ' ', $part));
            if ($part === '') {
                continue;
            }

            $tokens = explode(' ', $part, 2);
            $name   = strtolower($tokens[0]);
            $value  = isset($tokens[1]) ? trim($tokens[1]) : '';

            if ($name === 'report-uri' || $name === 'report-to') {
                continue; // The plugin manages reporting directives itself.
            }

            if (in_array($name, self::source_directives(), true)) {
                $directives[$name] = $value;
            } elseif (in_array($name, self::flag_directives(), true)) {
                $directives[$name] = '';
            }
        }

        return $directives;
    }

    /**
     * Build the policy string (without reporting directives).
     *
     * @param string $context 'enforce'|'report-only' — passed to the filter
     *                        so extensions can vary the policy per header,
     *                        and selects that header's nonce setting.
     * @param bool $allow_nonce False to never add a nonce (wp-admin).
     * @return string
     */
    public function build_policy_string( $context = 'report-only', $allow_nonce = true ) {
        return $this->compile($this->get_directives(), $context, $allow_nonce);
    }

    /**
     * The single path every header value goes through: filter, normalize,
     * add script-src extras (nonce, 'strict-dynamic', 'report-sample'),
     * serialize.
     *
     * @param array $directives directive => source string.
     * @param string $context 'enforce'|'report-only'.
     * @param bool $allow_nonce
     * @return string
     */
    private function compile( $directives, $context, $allow_nonce ) {
        /**
         * Filter the CSP directives before the header is built.
         *
         * Runs before the plugin adds its nonce / 'strict-dynamic' /
         * 'report-sample' sources, so rebuilding script-src here cannot drop
         * them.
         *
         * @param array $directives directive => source string ('' for flags).
         * @param string $context 'enforce' or 'report-only'.
         */
        $directives = apply_filters('csp_policy_directives', $directives, $context);

        $normalized = array();

        foreach ( (array) $directives as $name => $value) {
            $name  = strtolower(trim($name));
            $value = trim(preg_replace('/\s+/', ' ', (string) $value));

            if ($name === '') {
                continue;
            }

            $normalized[$name] = $value;
        }

        $normalized = $this->apply_script_src_options($normalized, $context, $allow_nonce);

        $parts = array();

        foreach ($normalized as $name => $value) {
            $parts[] = $value === '' ? $name : $name . ' ' . $value;
        }

        return implode('; ', $parts);
    }

    /**
     * Get the plugin options.
     *
     * @return array
     */
    private function get_options() {
        return get_option('csp_reporting_options', array());
    }

    /**
     * Whether nonce mode is on for a header, honoring the WordPress version
     * requirement.
     *
     * @param string $context 'enforce' (Content-Security-Policy) or
     *                        'report-only' (Content-Security-Policy-Report-Only).
     * @return bool
     */
    public function is_nonce_enabled_for( $context ) {
        if ( ! CSP_Nonce::is_supported()) {
            return false;
        }

        $options = $this->get_options();
        $key     = $context === 'enforce' ? 'csp_nonce_enforce' : 'csp_nonce_report_only';

        return ! empty($options[$key]);
    }

    /**
     * Get the header contexts the current mode sends.
     *
     * @return string[] Subset of 'enforce', 'report-only'.
     */
    public function get_header_contexts() {
        $mode = $this->get_mode();

        if ($mode === self::MODE_BOTH) {
            return array( 'enforce', 'report-only' );
        }

        return array( $mode === self::MODE_ENFORCE ? 'enforce' : 'report-only' );
    }

    /**
     * Whether any header sent on front-end requests carries a nonce, i.e.
     * whether WordPress-printed scripts need stamping.
     *
     * @return bool
     */
    public function is_nonce_active() {
        $options = $this->get_options();

        if (empty($options['csp_enabled'])) {
            return false;
        }

        foreach ($this->get_header_contexts() as $context) {
            if ($this->is_nonce_enabled_for($context)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Add the configured script-src extras for one header.
     *
     * @param array $directives Normalized directive => sources.
     * @param string $context
     * @param bool $allow_nonce
     * @return array
     */
    private function apply_script_src_options( $directives, $context, $allow_nonce ) {
        $options = $this->get_options();
        $nonce   = array();

        if ($allow_nonce && $this->is_nonce_enabled_for($context)) {
            $nonce[] = "'nonce-" . CSP_Nonce::get() . "'";

            if ( ! empty($options['csp_strict_dynamic'])) {
                $nonce[] = "'strict-dynamic'";
            }
        }

        $samples = ! empty($options['csp_report_sample']) ? array( "'report-sample'" ) : array();

        return self::add_script_sources($directives, $nonce, $samples);
    }

    /**
     * Add sources to a policy's script directives.
     *
     * When the policy has no script-src, one is created from a copy of
     * default-src so scripts keep exactly the sources they fell back to
     * before. The nonce is never added to default-src itself: style-src
     * also falls back to default-src, and a nonce there would make browsers
     * ignore 'unsafe-inline' for styles.
     *
     * Existing sources ('unsafe-inline', hosts, 'self') are kept: browsers
     * that understand nonces ignore 'unsafe-inline', and with
     * 'strict-dynamic' they also ignore host and 'self' sources, so leaving
     * them in is the backward-compatible fallback for older browsers.
     *
     * @param array $directives Normalized directive => sources.
     * @param string[] $nonce_sources Nonce (and 'strict-dynamic'); added to
     *                                script-src and script-src-elem.
     * @param string[] $sample_sources 'report-sample'; added to script-src,
     *                                 script-src-elem, and script-src-attr.
     * @return array
     */
    public static function add_script_sources( $directives, $nonce_sources, $sample_sources = array() ) {
        if (empty($nonce_sources) && empty($sample_sources)) {
            return $directives;
        }

        if ( ! isset($directives['script-src'])) {
            if (isset($directives['default-src'])) {
                $directives = self::insert_after($directives, 'default-src', 'script-src', $directives['default-src']);
            } elseif ( ! empty($nonce_sources)) {
                // No script restriction at all: nonce mode is an explicit
                // opt-in to restrict scripts, so start an empty list.
                $directives['script-src'] = '';
            } else {
                // 'report-sample' alone must never start restricting
                // scripts; with no script policy nothing can be reported.
                return $directives;
            }
        }

        $targets = array(
            'script-src' => array_merge($nonce_sources, $sample_sources),
            'script-src-elem' => array_merge($nonce_sources, $sample_sources),
            'script-src-attr' => $sample_sources,
        );

        foreach ($targets as $name => $additions) {
            if (empty($additions) || ! isset($directives[$name])) {
                continue;
            }

            $current = trim($directives[$name]);

            // 'none' cannot be combined with other sources.
            $sources = ( $current === '' || strtolower($current) === "'none'" ) ? array() : explode(' ', $current);
            $lower   = array_map('strtolower', $sources);

            foreach ($additions as $source) {
                if ( ! in_array(strtolower($source), $lower, true)) {
                    $sources[] = $source;
                }
            }

            $directives[$name] = implode(' ', $sources);
        }

        return $directives;
    }

    /**
     * Insert a key after another, preserving order.
     *
     * @param array $items
     * @param string $after
     * @param string $key
     * @param mixed $value
     * @return array
     */
    private static function insert_after( $items, $after, $key, $value ) {
        $result = array();

        foreach ($items as $k => $v) {
            $result[$k] = $v;
            if ($k === $after) {
                $result[$key] = $value;
            }
        }

        return $result;
    }

    /**
     * The endpoint name used in Reporting-Endpoints / report-to.
     */
    const REPORT_TO_GROUP = 'csp-endpoint';

    /**
     * Reporting directives appended to every policy: legacy report-uri for
     * broad support plus report-to for the modern Reporting API (browsers
     * that understand report-to ignore report-uri).
     *
     * @param string $report_url
     * @return string
     */
    private function reporting_directives( $report_url ) {
        return '; report-uri ' . $report_url . '; report-to ' . self::REPORT_TO_GROUP;
    }

    /**
     * Get the CSP headers to send, as name => value.
     *
     * Includes a Reporting-Endpoints header defining the report-to group.
     *
     * @param string $report_url Violation report endpoint URL.
     * @param bool $allow_nonce False to never add a nonce, whatever the
     *                          settings (wp-admin, which nonce mode does not
     *                          cover).
     * @return array
     */
    public function get_headers( $report_url, $allow_nonce = true ) {
        $mode    = $this->get_mode();
        $headers = array();

        if ($mode === self::MODE_ENFORCE || $mode === self::MODE_BOTH) {
            $policy = $this->build_policy_string('enforce', $allow_nonce);
            if ($policy !== '') {
                $headers['Content-Security-Policy'] = $policy . $this->reporting_directives($report_url);
            }
        }

        if ($mode === self::MODE_REPORT_ONLY || $mode === self::MODE_BOTH) {
            // In dual mode the report-only header carries the stricter test
            // policy when one is configured, so a safe policy can be enforced
            // while the next iteration is evaluated.
            $policy = '';

            if ($mode === self::MODE_BOTH) {
                $options = $this->get_options();
                $test    = ! empty($options['csp_test_policy']) ? self::parse_policy_text($options['csp_test_policy']) : array();

                if ( ! empty($test)) {
                    $policy = $this->compile($test, 'report-only', $allow_nonce);
                }
            }

            if ($policy === '') {
                $policy = $this->build_policy_string('report-only', $allow_nonce);
            }

            if ($policy !== '') {
                $headers['Content-Security-Policy-Report-Only'] = $policy . $this->reporting_directives($report_url);
            }
        }

        if ( ! empty($headers)) {
            $headers['Reporting-Endpoints'] = self::REPORT_TO_GROUP . '="' . $report_url . '"';
        }

        return $headers;
    }

    /**
     * Map a violated-directive value to the base directive to modify.
     *
     * Browsers report granular directives (script-src-elem, style-src-attr);
     * sources belong on the base directive.
     *
     * @param string $violated_directive
     * @return string|false Base directive, or false when not editable.
     */
    public static function base_directive( $violated_directive ) {
        $name = strtolower(trim(explode(' ', trim( (string) $violated_directive))[0]));
        $name = preg_replace('/-(elem|attr)$/', '', $name);

        return in_array($name, self::source_directives(), true) ? $name : false;
    }

    /**
     * Extract an allowable source expression from a blocked URI.
     *
     * @param string $blocked_uri
     * @return string|false Origin (scheme://host[:port]), or false for
     *                      inline/eval/data pseudo-URIs.
     */
    public static function source_from_blocked_uri( $blocked_uri ) {
        $blocked_uri = trim( (string) $blocked_uri);

        if ($blocked_uri === '' || in_array($blocked_uri, array( 'inline', 'eval', 'wasm-eval', 'self', 'unsafe-eval' ), true)) {
            return false;
        }

        $parts = wp_parse_url($blocked_uri);

        if (empty($parts['scheme']) || empty($parts['host'])) {
            return false;
        }

        if ( ! in_array(strtolower($parts['scheme']), array( 'http', 'https', 'ws', 'wss' ), true)) {
            return false;
        }

        $origin = strtolower($parts['scheme']) . '://' . strtolower($parts['host']);

        if ( ! empty($parts['port'])) {
            $origin .= ':' . (int) $parts['port'];
        }

        // blocked-uri comes from unauthenticated reports, and parse_url()
        // accepts hosts containing spaces, quotes, ';' and markup — e.g.
        // "https://cdn.example.com 'unsafe-inline'/x.js". Anything that is
        // not a plain origin must never reach the policy or the admin UI.
        return self::is_valid_origin($origin) ? $origin : false;
    }

    /**
     * Check that a value is a plain origin: scheme://host[:port] with a DNS
     * hostname, IPv4 address, or bracketed IPv6 address — nothing that could
     * add a source keyword or directive to a policy.
     *
     * @param string $origin
     * @return bool
     */
    public static function is_valid_origin( $origin ) {
        $label = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';

        return (bool) preg_match(
            '#^(?:https?|wss?)://(?:(?:' . $label . '\.)*' . $label . '|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?$#',
            (string) $origin
        );
    }

    /**
     * Check whether an origin is already allowed for a (possibly granular)
     * directive in the stored policy.
     *
     * Matches the exact origin, a bare-host entry, or a '*' wildcard on the
     * base directive; falls back to default-src when the base directive is
     * not set, mirroring browser fallback behavior.
     *
     * @param string $violated_directive e.g. script-src-elem.
     * @param string $origin e.g. https://cdn.example.com.
     * @return bool
     */
    public function is_source_allowed( $violated_directive, $origin ) {
        $base = self::base_directive($violated_directive);

        if ( ! $base || $origin === '') {
            return false;
        }

        $directives = $this->get_directives();

        if ( ! isset($directives[$base]) && isset($directives['default-src']) && $base !== 'default-src') {
            $base = 'default-src';
        }

        if ( ! isset($directives[$base])) {
            return false;
        }

        $sources = array_filter(explode(' ', strtolower($directives[$base])));
        $host    = preg_replace('#^[a-z]+://#', '', strtolower($origin));

        foreach ($sources as $source) {
            if ($source === '*' || $source === strtolower($origin) || $source === $host) {
                return true;
            }
        }

        return false;
    }

    /**
     * Add a source to a directive and persist the policy.
     *
     * @param string $directive Base directive (must be a source directive).
     * @param string $source An origin (scheme://host[:port]); anything else
     *                       is rejected.
     * @return bool True when added, false when invalid or already present.
     */
    public function add_source( $directive, $source ) {
        if ( ! in_array($directive, self::source_directives(), true) || ! self::is_valid_origin($source)) {
            return false;
        }

        $directives = $this->get_directives();
        $current    = isset($directives[$directive]) ? $directives[$directive] : '';
        $sources    = $current === '' ? array() : explode(' ', $current);

        if (in_array($source, $sources, true)) {
            return false;
        }

        $sources[]              = $source;
        $directives[$directive] = implode(' ', $sources);

        $options                          = get_option('csp_reporting_options', array());
        $options['csp_policy_directives'] = $directives;
        update_option('csp_reporting_options', $options);

        return true;
    }
}
