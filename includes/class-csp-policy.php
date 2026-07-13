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
     *                        so extensions can vary the policy per header.
     * @return string
     */
    public function build_policy_string( $context = 'report-only' ) {
        $directives = $this->get_directives();

        /**
         * Filter the CSP directives before the header is built.
         *
         * @param array $directives directive => source string ('' for flags).
         * @param string $context 'enforce' or 'report-only'.
         */
        $directives = apply_filters('csp_policy_directives', $directives, $context);

        $parts = array();

        foreach ( (array) $directives as $name => $value) {
            $name  = strtolower(trim($name));
            $value = trim(preg_replace('/\s+/', ' ', (string) $value));

            if ($name === '') {
                continue;
            }

            $parts[] = $value === '' ? $name : $name . ' ' . $value;
        }

        return implode('; ', $parts);
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
     * @return array
     */
    public function get_headers( $report_url ) {
        $mode    = $this->get_mode();
        $headers = array();

        if ($mode === self::MODE_ENFORCE || $mode === self::MODE_BOTH) {
            $policy = $this->build_policy_string('enforce');
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
                $options = get_option('csp_reporting_options', array());
                if ( ! empty($options['csp_test_policy'])) {
                    $test_directives = self::parse_policy_text($options['csp_test_policy']);

                    /** This filter is documented in includes/class-csp-policy.php */
                    $test_directives = apply_filters('csp_policy_directives', $test_directives, 'report-only');

                    $parts = array();
                    foreach ( (array) $test_directives as $name => $value) {
                        $parts[] = $value === '' ? $name : $name . ' ' . $value;
                    }
                    $policy = implode('; ', $parts);
                }
            }

            if ($policy === '') {
                $policy = $this->build_policy_string('report-only');
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

        return $origin;
    }

    /**
     * Add a source to a directive and persist the policy.
     *
     * @param string $directive Base directive (must be a source directive).
     * @param string $source Source expression (an origin).
     * @return bool True when added, false when invalid or already present.
     */
    public function add_source( $directive, $source ) {
        if ( ! in_array($directive, self::source_directives(), true) || $source === '') {
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
