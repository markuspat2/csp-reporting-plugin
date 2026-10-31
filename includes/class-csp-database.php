<?php
/**
 * CSP Database Class
 *
 * Owns the wp_csp_violations table: schema, deduplicated inserts, queries,
 * pruning, and migration of legacy 1.x file logs.
 */

if ( ! defined('ABSPATH')) {
    exit;
}

class CSP_Database {

    /**
     * Bump when the schema changes; compared against the stored option.
     *
     * v2: blocked_origin column; dedup hash computed on normalized URIs
     * (query strings/fragments stripped) with existing duplicates merged.
     *
     * v3: script_sample column. Inline/eval violations hash on their source
     * location or sample so distinct inline scripts get separate rows;
     * URL-based hashes are unchanged and existing rows are not rewritten.
     */
    const DB_VERSION = '3';

    const DB_VERSION_OPTION   = 'csp_reporting_db_version';
    const UPGRADE_LOCK_OPTION = 'csp_reporting_upgrade_lock';

    /**
     * Seconds after which an upgrade lock is considered abandoned.
     */
    const UPGRADE_LOCK_TTL = 300;
    const MIGRATED_OPTION  = 'csp_reporting_logs_migrated';

    /**
     * Get the violations table name.
     *
     * @return string
     */
    public static function table_name() {
        global $wpdb;
        return $wpdb->prefix . 'csp_violations';
    }

    /**
     * Create or update the violations table.
     */
    public static function install() {
        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $table           = self::table_name();
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            report_hash CHAR(40) NOT NULL DEFAULT '',
            severity VARCHAR(10) NOT NULL DEFAULT 'low',
            directive VARCHAR(64) NOT NULL DEFAULT '',
            blocked_origin VARCHAR(255) NOT NULL DEFAULT '',
            blocked_uri TEXT NULL,
            document_uri TEXT NULL,
            source_file TEXT NULL,
            line_number INT(11) UNSIGNED NOT NULL DEFAULT 0,
            column_number INT(11) UNSIGNED NOT NULL DEFAULT 0,
            script_sample VARCHAR(255) NULL,
            disposition VARCHAR(10) NOT NULL DEFAULT 'report',
            user_agent VARCHAR(255) NOT NULL DEFAULT '',
            client_ip VARCHAR(45) NOT NULL DEFAULT '',
            hit_count BIGINT(20) UNSIGNED NOT NULL DEFAULT 1,
            first_seen DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00',
            last_seen DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00',
            PRIMARY KEY  (id),
            UNIQUE KEY report_hash (report_hash),
            KEY severity (severity),
            KEY directive (directive),
            KEY blocked_origin (blocked_origin),
            KEY last_seen (last_seen)
        ) {$charset_collate};";

        dbDelta($sql);

        // Only record the new version once the schema really has it, so a
        // failed ALTER (e.g. a DB user without ALTER privilege) is retried
        // instead of leaving inserts failing against a missing column.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        if ($wpdb->get_var($wpdb->prepare("SHOW COLUMNS FROM {$table} LIKE %s", 'script_sample'))) {
            update_option(self::DB_VERSION_OPTION, self::DB_VERSION);
        }
    }

    /**
     * Install/upgrade the schema when the stored version differs.
     *
     * Cheap (one autoloaded option read) and run on every request, so the
     * report endpoint never writes to a table that is missing a column
     * because no admin page has loaded since the plugin was updated.
     */
    public function maybe_upgrade_schema() {
        $installed_version = get_option(self::DB_VERSION_OPTION);

        if ($installed_version === self::DB_VERSION) {
            return;
        }

        // On a busy site many requests see the old version at once; only the
        // one that takes the lock runs the ALTER, the rest carry on.
        if ( ! self::acquire_upgrade_lock()) {
            return;
        }

        self::install();

        if ($installed_version === '1') {
            $this->upgrade_to_v2();
        }

        self::release_upgrade_lock();

        // v2 → v3 only adds the nullable script_sample column (handled by
        // install()). Existing rows keep their hashes: URL-based hashes are
        // unchanged, and the old one-row-per-page inline aggregates simply
        // age out through retention while new reports land in finer rows.
    }

    /**
     * Take the schema-upgrade lock.
     *
     * INSERT IGNORE on the options table is atomic, so exactly one of any
     * number of concurrent requests gets it (the pattern core's
     * WP_Upgrader::create_lock() uses). A lock older than UPGRADE_LOCK_TTL is
     * treated as abandoned and taken over.
     *
     * @return bool
     */
    private static function acquire_upgrade_lock() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $created = $wpdb->query($wpdb->prepare(
            "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
            self::UPGRADE_LOCK_OPTION,
            time()
        ));

        if ($created) {
            return true;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $locked_at = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
            self::UPGRADE_LOCK_OPTION
        ));

        if ($locked_at > time() - self::UPGRADE_LOCK_TTL) {
            return false;
        }

        // Abandoned: take it over only if nobody else just did.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return (bool) $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND option_value = %s",
            time(),
            self::UPGRADE_LOCK_OPTION,
            $locked_at
        ));
    }

    /**
     * Release the schema-upgrade lock.
     */
    private static function release_upgrade_lock() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name = %s", self::UPGRADE_LOCK_OPTION));
        wp_cache_delete(self::UPGRADE_LOCK_OPTION, 'options');
    }

    /**
     * Upgrade the schema if needed and migrate legacy file logs once.
     *
     * @param CSP_Logger $logger Used to parse legacy log files.
     */
    public function maybe_upgrade( $logger ) {
        $this->maybe_upgrade_schema();

        if ( ! get_option(self::MIGRATED_OPTION)) {
            // On multisite the 1.x log directory is shared by every site, so
            // importing it per site would copy each site's violations into
            // all the others. Only the main site imports them.
            if ( ! is_multisite() || is_main_site()) {
                $this->migrate_legacy_logs($logger);
            }
            update_option(self::MIGRATED_OPTION, 1);
        }
    }

    /**
     * Compute the deduplication hash for a violation.
     *
     * Two reports of the same directive blocking the same URI (ignoring
     * query strings and fragments) on the same page path are one violation
     * pattern; they increment a counter instead of inserting a new row.
     *
     * Inline and eval violations all share the blocked-uri keyword, so for
     * those the hash also includes where the code is: the source file plus
     * the code sample when the report has one, otherwise the line number.
     * The sample is preferred because line numbers shift when page content
     * above the script changes. URL-based hashes are exactly as before v3.
     *
     * @param string $directive
     * @param string $blocked_uri
     * @param string $document_uri
     * @param string $source_file
     * @param int $line_number
     * @param string $sample
     * @return string
     */
    public static function report_hash( $directive, $blocked_uri, $document_uri, $source_file = '', $line_number = 0, $sample = '' ) {
        $key = $directive . '|'
            . CSP_Utils::normalize_uri_for_hash($blocked_uri) . '|'
            . CSP_Utils::normalize_uri_for_hash($document_uri);

        if (CSP_Utils::is_inline_like_uri($blocked_uri)) {
            $key .= '|' . CSP_Utils::normalize_uri_for_hash($source_file) . '|'
                . ( (string) $sample !== '' ? 'sample:' . $sample : 'line:' . (int) $line_number );
        }

        return sha1($key);
    }

    /**
     * v1 → v2 data migration: recompute every row's hash on normalized URIs,
     * backfill blocked_origin, and merge rows that now collide (sum
     * hit_count, keep earliest first_seen / latest last_seen, keep the
     * lowest id).
     */
    private function upgrade_to_v2() {
        global $wpdb;

        $table = self::table_name();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $rows = $wpdb->get_results(
            "SELECT id, directive, blocked_uri, document_uri, source_file, line_number, hit_count, first_seen, last_seen FROM {$table} ORDER BY id ASC",
            ARRAY_A
        );

        $groups = array();

        foreach ( (array) $rows as $row) {
            $hash = self::report_hash($row['directive'], $row['blocked_uri'], $row['document_uri'], $row['source_file'], $row['line_number']);

            if ( ! isset($groups[$hash])) {
                $origin        = CSP_Policy::source_from_blocked_uri($row['blocked_uri']);
                $groups[$hash] = array(
                    'id' => (int) $row['id'],
                    'blocked_origin' => $origin ? $origin : '',
                    'hit_count' => (int) $row['hit_count'],
                    'first_seen' => $row['first_seen'],
                    'last_seen' => $row['last_seen'],
                    'duplicate_ids' => array(),
                );
                continue;
            }

            $group                    = &$groups[$hash];
            $group['hit_count']      += (int) $row['hit_count'];
            $group['first_seen']      = min($group['first_seen'], $row['first_seen']);
            $group['last_seen']       = max($group['last_seen'], $row['last_seen']);
            $group['duplicate_ids'][] = (int) $row['id'];
            unset($group);
        }

        // Delete duplicates first so hash updates can't hit the unique key.
        $all_duplicate_ids = array();
        foreach ($groups as $group) {
            $all_duplicate_ids = array_merge($all_duplicate_ids, $group['duplicate_ids']);
        }

        if ( ! empty($all_duplicate_ids)) {
            $this->delete_violations($all_duplicate_ids);
        }

        foreach ($groups as $hash => $group) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            $wpdb->update(
                $table,
                array(
                    'report_hash' => $hash,
                    'blocked_origin' => $group['blocked_origin'],
                    'hit_count' => $group['hit_count'],
                    'first_seen' => $group['first_seen'],
                    'last_seen' => $group['last_seen'],
                ),
                array( 'id' => $group['id'] )
            );
        }
    }

    /**
     * Insert a violation, or bump its counter when the pattern is known.
     *
     * @param array $violation {
     *     @type string $severity
     *     @type string $directive
     *     @type string $blocked_uri
     *     @type string $document_uri
     *     @type string $source_file
     *     @type int    $line_number
     *     @type int    $column_number
     *     @type string $script_sample
     *     @type string $disposition
     *     @type string $user_agent
     *     @type string $client_ip
     *     @type string $seen_at MySQL datetime; defaults to now.
     * }
     * @return bool
     */
    public function insert_violation( $violation ) {
        global $wpdb;

        $defaults  = array(
            'severity' => 'low',
            'directive' => '',
            'blocked_uri' => '',
            'document_uri' => '',
            'source_file' => '',
            'line_number' => 0,
            'column_number' => 0,
            'script_sample' => '',
            'disposition' => 'report',
            'user_agent' => '',
            'client_ip' => '',
            'seen_at' => current_time('mysql'),
        );
        $violation = wp_parse_args($violation, $defaults);

        $sample = CSP_Utils::sanitize_sample($violation['script_sample']);
        $table  = self::table_name();

        // Tables still on 3-byte utf8 reject 4-byte characters (emoji are
        // common in inline code), and wpdb then drops the whole insert.
        // Strip them for such columns; utf8mb4 tables keep them.
        if ($sample !== '' && preg_match('/[\x{10000}-\x{10FFFF}]/u', $sample)) {
            $stripped = $wpdb->strip_invalid_text_for_column($table, 'script_sample', $sample);
            $sample   = is_string($stripped) ? $stripped : '';
        }

        $hash = self::report_hash(
            $violation['directive'],
            $violation['blocked_uri'],
            $violation['document_uri'],
            $violation['source_file'],
            $violation['line_number'],
            $sample
        );

        $origin = CSP_Policy::source_from_blocked_uri($violation['blocked_uri']);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $result = $wpdb->query($wpdb->prepare(
            "INSERT INTO {$table}
                (report_hash, severity, directive, blocked_origin, blocked_uri, document_uri, source_file,
                 line_number, column_number, script_sample, disposition, user_agent, client_ip,
                 hit_count, first_seen, last_seen)
             VALUES (%s, %s, %s, %s, %s, %s, %s, %d, %d, NULLIF(%s, ''), %s, %s, %s, 1, %s, %s)
             ON DUPLICATE KEY UPDATE
                hit_count = hit_count + 1,
                last_seen = VALUES(last_seen),
                severity = VALUES(severity),
                disposition = VALUES(disposition)",
            $hash,
            $violation['severity'],
            substr($violation['directive'], 0, 64),
            $origin ? substr($origin, 0, 255) : '',
            $violation['blocked_uri'],
            $violation['document_uri'],
            $violation['source_file'],
            (int) $violation['line_number'],
            (int) $violation['column_number'],
            $sample,
            substr($violation['disposition'], 0, 10),
            substr($violation['user_agent'], 0, 255),
            substr($violation['client_ip'], 0, 45),
            $violation['seen_at'],
            $violation['seen_at']
        ));

        return $result !== false;
    }

    /**
     * Build the WHERE clause for violation queries.
     *
     * @param array $args
     * @return string Prepared WHERE clause (without the WHERE keyword).
     */
    private function build_where( $args ) {
        global $wpdb;

        $where = array( '1=1' );

        if ( ! empty($args['severity'])) {
            $where[] = $wpdb->prepare('severity = %s', $args['severity']);
        }

        if ( ! empty($args['directive'])) {
            $where[] = $wpdb->prepare('directive = %s', $args['directive']);
        }

        if ( ! empty($args['search'])) {
            $like    = '%' . $wpdb->esc_like($args['search']) . '%';
            $where[] = $wpdb->prepare('(blocked_uri LIKE %s OR document_uri LIKE %s OR source_file LIKE %s OR script_sample LIKE %s)', $like, $like, $like, $like);
        }

        if ( ! empty($args['since'])) {
            $where[] = $wpdb->prepare('last_seen >= %s', $args['since']);
        }

        return implode(' AND ', $where);
    }

    /**
     * Query violations.
     *
     * @param array $args severity, directive, search, since, orderby, order, per_page, paged
     * @return array[] Rows as associative arrays.
     */
    public function get_violations( $args = array() ) {
        global $wpdb;

        $defaults = array(
            'orderby' => 'last_seen',
            'order' => 'DESC',
            'per_page' => 20,
            'paged' => 1,
        );
        $args     = wp_parse_args($args, $defaults);

        $allowed_orderby = array( 'severity', 'directive', 'hit_count', 'last_seen', 'first_seen', 'id' );
        $orderby         = in_array($args['orderby'], $allowed_orderby, true) ? $args['orderby'] : 'last_seen';
        $order           = strtoupper($args['order']) === 'ASC' ? 'ASC' : 'DESC';

        $per_page = max(1, (int) $args['per_page']);
        $offset   = ( max(1, (int) $args['paged']) - 1 ) * $per_page;

        $table = self::table_name();
        $where = $this->build_where($args);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return $wpdb->get_results(
            "SELECT * FROM {$table} WHERE {$where} ORDER BY {$orderby} {$order} LIMIT {$offset}, {$per_page}",
            ARRAY_A
        );
    }

    /**
     * Count violations matching the filters.
     *
     * @param array $args
     * @return int
     */
    public function count_violations( $args = array() ) {
        global $wpdb;

        $table = self::table_name();
        $where = $this->build_where($args);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table} WHERE {$where}");
    }

    /**
     * Get a single violation by id.
     *
     * @param int $id
     * @return array|null
     */
    public function get_violation( $id ) {
        global $wpdb;

        $table = self::table_name();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE id = %d", (int) $id), ARRAY_A);
    }

    /**
     * Delete violations by id.
     *
     * @param int[] $ids
     * @return int Rows deleted.
     */
    public function delete_violations( $ids ) {
        global $wpdb;

        $ids = array_filter(array_map('intval', (array) $ids));
        if (empty($ids)) {
            return 0;
        }

        $table        = self::table_name();
        $placeholders = implode(',', array_fill(0, count($ids), '%d'));

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- placeholders are %d, built above.
        return (int) $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE id IN ({$placeholders})", $ids));
    }

    /**
     * Delete all violations.
     *
     * @return int Rows deleted.
     */
    public function clear_all() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return (int) $wpdb->query('DELETE FROM ' . self::table_name());
    }

    /**
     * Delete violations not seen within the retention window.
     *
     * @param int $retention_days
     * @return int Rows deleted.
     */
    public function prune( $retention_days ) {
        global $wpdb;

        // first_seen/last_seen are stored in site-local time
        // (current_time('mysql')), so cutoffs must be local too.
        $cutoff = wp_date('Y-m-d H:i:s', time() - ( (int) $retention_days * DAY_IN_SECONDS ));
        $table  = self::table_name();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return (int) $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE last_seen < %s", $cutoff));
    }

    /**
     * Count high-severity violations seen since a given time.
     *
     * @param string $since MySQL datetime.
     * @return int
     */
    public function count_high_since( $since ) {
        global $wpdb;

        $table = self::table_name();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE severity = 'high' AND last_seen >= %s",
            $since
        ));
    }

    /**
     * Get distinct directives present in the table (for filter dropdowns).
     *
     * @return string[]
     */
    public function get_distinct_directives() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return $wpdb->get_col('SELECT DISTINCT directive FROM ' . self::table_name() . ' ORDER BY directive');
    }

    /**
     * Roll violations up by blocked origin + directive.
     *
     * Rows without a blocked origin (inline/eval/data violations) are
     * excluded — they can't be fixed by allowing a source.
     *
     * @return array[] blocked_origin, directive, hits, pages, max_severity_rank, last_seen
     */
    public function get_violations_by_source() {
        global $wpdb;

        $table = self::table_name();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return (array) $wpdb->get_results(
            "SELECT blocked_origin, directive,
                    SUM(hit_count) AS hits,
                    COUNT(DISTINCT document_uri) AS pages,
                    MAX(FIELD(severity, 'low', 'medium', 'high')) AS max_severity_rank,
                    MAX(last_seen) AS last_seen
             FROM {$table}
             WHERE blocked_origin != ''
             GROUP BY blocked_origin, directive
             ORDER BY hits DESC",
            ARRAY_A
        );
    }

    /**
     * Count violation patterns that have no allowable origin (inline, eval,
     * data: and similar) — these need a policy change, not a new source.
     *
     * @return int
     */
    public function count_sourceless_violations() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return (int) $wpdb->get_var(
            'SELECT COUNT(*) FROM ' . self::table_name() . " WHERE blocked_origin = ''"
        );
    }

    /**
     * Get aggregate statistics for the last N days.
     *
     * @param int $days
     * @return array
     */
    public function get_stats( $days = 7 ) {
        global $wpdb;

        $table = self::table_name();
        $since = wp_date('Y-m-d H:i:s', time() - ( (int) $days * DAY_IN_SECONDS ));

        $stats = array(
            'total_hits' => 0,
            'unique_patterns' => 0,
            'by_severity' => array( 'low' => 0, 'medium' => 0, 'high' => 0 ),
            'top_blocked' => array(),
            'by_day' => array(),
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $totals = $wpdb->get_row($wpdb->prepare(
            "SELECT COALESCE(SUM(hit_count), 0) AS hits, COUNT(*) AS patterns FROM {$table} WHERE last_seen >= %s",
            $since
        ), ARRAY_A);

        if ($totals) {
            $stats['total_hits']      = (int) $totals['hits'];
            $stats['unique_patterns'] = (int) $totals['patterns'];
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $severities = $wpdb->get_results($wpdb->prepare(
            "SELECT severity, SUM(hit_count) AS hits FROM {$table} WHERE last_seen >= %s GROUP BY severity",
            $since
        ), ARRAY_A);

        foreach ( (array) $severities as $row) {
            if (isset($stats['by_severity'][$row['severity']])) {
                $stats['by_severity'][$row['severity']] = (int) $row['hits'];
            }
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $stats['top_blocked'] = (array) $wpdb->get_results($wpdb->prepare(
            "SELECT blocked_uri, directive, SUM(hit_count) AS hits
             FROM {$table} WHERE last_seen >= %s
             GROUP BY blocked_uri, directive ORDER BY hits DESC LIMIT 5",
            $since
        ), ARRAY_A);

        // Daily buckets (by last_seen) for sparklines.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $daily = $wpdb->get_results($wpdb->prepare(
            "SELECT DATE(last_seen) AS day, SUM(hit_count) AS hits
             FROM {$table} WHERE last_seen >= %s GROUP BY DATE(last_seen)",
            $since
        ), ARRAY_A);

        $by_day = array();
        foreach ( (array) $daily as $row) {
            $by_day[$row['day']] = (int) $row['hits'];
        }

        for ($i = $days - 1; $i >= 0; $i--) {
            $day                   = wp_date('Y-m-d', time() - ( $i * DAY_IN_SECONDS ));
            $stats['by_day'][$day] = isset($by_day[$day]) ? $by_day[$day] : 0;
        }

        return $stats;
    }

    /**
     * Import violations from legacy 1.x log files (best effort).
     *
     * Files are left in place after import.
     *
     * @param CSP_Logger $logger
     * @return int Entries imported.
     */
    public function migrate_legacy_logs( $logger ) {
        $imported = 0;

        foreach ($logger->get_log_files() as $file) {
            foreach ($logger->read_log_entries($file) as $entry) {
                if ( ! isset($entry['report_data']['csp-report'])) {
                    continue;
                }

                $report = $entry['report_data']['csp-report'];

                if (empty($report['document-uri']) || empty($report['violated-directive'])) {
                    continue;
                }

                $this->insert_violation(array(
                    'severity' => isset($entry['report_data']['severity']) ? $entry['report_data']['severity'] : 'low',
                    'directive' => $report['violated-directive'],
                    'blocked_uri' => isset($report['blocked-uri']) ? $report['blocked-uri'] : '',
                    'document_uri' => $report['document-uri'],
                    'source_file' => isset($report['source-file']) ? $report['source-file'] : '',
                    'line_number' => isset($report['line-number']) ? (int) $report['line-number'] : 0,
                    'column_number' => isset($report['column-number']) ? (int) $report['column-number'] : 0,
                    'script_sample' => isset($report['script-sample']) ? $report['script-sample'] : '',
                    'disposition' => isset($report['disposition']) ? $report['disposition'] : 'report',
                    'user_agent' => isset($entry['user_agent']) ? $entry['user_agent'] : '',
                    'client_ip' => isset($entry['ip_address']) ? $entry['ip_address'] : '',
                    'seen_at' => isset($entry['timestamp']) ? $entry['timestamp'] : current_time('mysql'),
                ));

                ++$imported;
            }
        }

        return $imported;
    }
}
