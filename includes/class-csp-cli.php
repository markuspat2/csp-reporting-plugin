<?php
/**
 * WP-CLI commands for CSP Reporting.
 *
 * Registered as `wp csp ...` when WP-CLI is present. Designed for scripting
 * across many sites (agency fleets): status checks, policy edits, and
 * violation triage without the admin UI.
 */

if ( ! defined('ABSPATH')) {
    exit;
}

class CSP_CLI {

    /**
     * @var CSP_Database
     */
    private $database;

    /**
     * @var CSP_Reporter
     */
    private $reporter;

    /**
     * Constructor
     *
     * @param CSP_Database $database
     * @param CSP_Reporter $reporter
     */
    public function __construct( $database, $reporter ) {
        $this->database = $database;
        $this->reporter = $reporter;
    }

    /**
     * Show plugin status: mode, endpoint, and 7-day violation stats.
     *
     * ## EXAMPLES
     *
     *     wp csp status
     *
     * @subcommand status
     */
    public function status( $args, $assoc_args ) {
        $options = get_option('csp_reporting_options', array());
        $policy  = new CSP_Policy();
        $stats   = $this->database->get_stats(7);

        $rows = array(
            array( 'field' => 'enabled', 'value' => ! empty($options['csp_enabled']) ? 'yes' : 'no' ),
            array( 'field' => 'mode', 'value' => $policy->get_mode() ),
            array( 'field' => 'endpoint', 'value' => CSP_Utils::get_report_endpoint_url() ),
            array( 'field' => 'reports_7d', 'value' => $stats['total_hits'] ),
            array( 'field' => 'patterns_7d', 'value' => $stats['unique_patterns'] ),
            array( 'field' => 'high_7d', 'value' => $stats['by_severity']['high'] ),
        );

        WP_CLI\Utils\format_items('table', $rows, array( 'field', 'value' ));
    }

    /**
     * Get or set the CSP policy.
     *
     * ## OPTIONS
     *
     * <action>
     * : get or set.
     *
     * [<directive>]
     * : Directive to set (e.g. script-src). Required for set.
     *
     * [<sources>]
     * : Space-separated source list (quote it). Empty string removes the
     *   directive. Required for set.
     *
     * [--format=<format>]
     * : Output format for get: table, json, csv, yaml. Default table.
     *
     * ## EXAMPLES
     *
     *     wp csp policy get
     *     wp csp policy get --format=json
     *     wp csp policy set script-src "'self' https://cdn.example.com"
     *     wp csp policy set frame-src ""
     *
     * @subcommand policy
     */
    public function policy( $args, $assoc_args ) {
        $action = isset($args[0]) ? $args[0] : 'get';
        $policy = new CSP_Policy();

        if ($action === 'get') {
            $directives = $policy->get_directives();
            $format     = isset($assoc_args['format']) ? $assoc_args['format'] : 'table';

            $rows = array();
            foreach ($directives as $directive => $sources) {
                $rows[] = array( 'directive' => $directive, 'sources' => $sources );
            }

            WP_CLI\Utils\format_items($format, $rows, array( 'directive', 'sources' ));
            return;
        }

        if ($action === 'set') {
            if ( ! isset($args[1]) || ! array_key_exists(2, $args)) {
                WP_CLI::error('Usage: wp csp policy set <directive> <sources>');
            }

            $directive = strtolower($args[1]);
            $sources   = trim($args[2]);

            $valid = array_merge(CSP_Policy::source_directives(), CSP_Policy::flag_directives());
            if ( ! in_array($directive, $valid, true)) {
                WP_CLI::error(sprintf('Unknown directive %s. Valid: %s', $directive, implode(', ', $valid)));
            }

            $options    = get_option('csp_reporting_options', array());
            $directives = $policy->get_directives();

            if ($sources === '' && ! in_array($directive, CSP_Policy::flag_directives(), true)) {
                unset($directives[$directive]);
                WP_CLI::log(sprintf('Removed %s.', $directive));
            } else {
                $directives[$directive] = in_array($directive, CSP_Policy::flag_directives(), true) ? '' : $sources;
                WP_CLI::log(sprintf('Set %s to: %s', $directive, $sources));
            }

            $options['csp_policy_directives'] = $directives;
            update_option('csp_reporting_options', $options);

            WP_CLI::success('Policy updated.');
            return;
        }

        WP_CLI::error("Unknown action '{$action}'. Use get or set.");
    }

    /**
     * List or clear recorded violations.
     *
     * ## OPTIONS
     *
     * <action>
     * : list or clear.
     *
     * [--severity=<severity>]
     * : Filter by severity (low, medium, high).
     *
     * [--directive=<directive>]
     * : Filter by directive.
     *
     * [--limit=<limit>]
     * : Max rows for list. Default 50.
     *
     * [--format=<format>]
     * : Output format: table, json, csv, yaml. Default table.
     *
     * [--yes]
     * : Skip the confirmation prompt for clear.
     *
     * ## EXAMPLES
     *
     *     wp csp violations list --severity=high --format=csv
     *     wp csp violations clear --yes
     *
     * @subcommand violations
     */
    public function violations( $args, $assoc_args ) {
        $action = isset($args[0]) ? $args[0] : 'list';

        if ($action === 'list') {
            $query = array(
                'per_page' => isset($assoc_args['limit']) ? (int) $assoc_args['limit'] : 50,
                'paged' => 1,
            );

            if ( ! empty($assoc_args['severity'])) {
                $query['severity'] = $assoc_args['severity'];
            }
            if ( ! empty($assoc_args['directive'])) {
                $query['directive'] = $assoc_args['directive'];
            }

            $rows   = $this->database->get_violations($query);
            $format = isset($assoc_args['format']) ? $assoc_args['format'] : 'table';

            WP_CLI\Utils\format_items(
                $format,
                $rows,
                array( 'id', 'severity', 'directive', 'blocked_uri', 'document_uri', 'hit_count', 'last_seen' )
            );
            return;
        }

        if ($action === 'clear') {
            WP_CLI::confirm('Delete ALL recorded violations?', $assoc_args);
            $deleted = $this->database->clear_all();
            WP_CLI::success(sprintf('%d violations deleted.', $deleted));
            return;
        }

        WP_CLI::error("Unknown action '{$action}'. Use list or clear.");
    }

    /**
     * Send a synthetic test report through the processing pipeline.
     *
     * ## EXAMPLES
     *
     *     wp csp test-report
     *
     * @subcommand test-report
     */
    public function test_report( $args, $assoc_args ) {
        $stored = $this->reporter->process_report($this->reporter->create_test_report());

        if ($stored) {
            WP_CLI::success('Test report recorded. Run `wp csp violations list` to see it.');
        } else {
            WP_CLI::error('Test report was not recorded (check ignore patterns and database).');
        }
    }
}
