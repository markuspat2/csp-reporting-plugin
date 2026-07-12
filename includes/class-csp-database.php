<?php
/**
 * CSP Database Class
 *
 * Owns the wp_csp_violations table: schema, deduplicated inserts, queries,
 * pruning, and migration of legacy 1.x file logs.
 */

if (!defined('ABSPATH')) {
    exit;
}

class CSP_Database {

    /**
     * Bump when the schema changes; compared against the stored option.
     */
    const DB_VERSION = '1';

    const DB_VERSION_OPTION = 'csp_reporting_db_version';
    const MIGRATED_OPTION = 'csp_reporting_logs_migrated';

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

        $table = self::table_name();
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            report_hash CHAR(40) NOT NULL DEFAULT '',
            severity VARCHAR(10) NOT NULL DEFAULT 'low',
            directive VARCHAR(64) NOT NULL DEFAULT '',
            blocked_uri TEXT NULL,
            document_uri TEXT NULL,
            source_file TEXT NULL,
            line_number INT(11) UNSIGNED NOT NULL DEFAULT 0,
            column_number INT(11) UNSIGNED NOT NULL DEFAULT 0,
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
            KEY last_seen (last_seen)
        ) {$charset_collate};";

        dbDelta($sql);

        update_option(self::DB_VERSION_OPTION, self::DB_VERSION);
    }

    /**
     * Install/upgrade the schema if needed and migrate legacy file logs once.
     *
     * @param CSP_Logger $logger Used to parse legacy log files.
     */
    public function maybe_upgrade($logger) {
        if (get_option(self::DB_VERSION_OPTION) !== self::DB_VERSION) {
            self::install();
        }

        if (!get_option(self::MIGRATED_OPTION)) {
            $this->migrate_legacy_logs($logger);
            update_option(self::MIGRATED_OPTION, 1);
        }
    }

    /**
     * Compute the deduplication hash for a violation.
     *
     * Two reports of the same directive blocking the same URI on the same
     * page are one violation pattern; they increment a counter instead of
     * inserting a new row.
     *
     * @param string $directive
     * @param string $blocked_uri
     * @param string $document_uri
     * @return string
     */
    public static function report_hash($directive, $blocked_uri, $document_uri) {
        return sha1($directive . '|' . $blocked_uri . '|' . $document_uri);
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
     *     @type string $disposition
     *     @type string $user_agent
     *     @type string $client_ip
     *     @type string $seen_at MySQL datetime; defaults to now.
     * }
     * @return bool
     */
    public function insert_violation($violation) {
        global $wpdb;

        $defaults = array(
            'severity' => 'low',
            'directive' => '',
            'blocked_uri' => '',
            'document_uri' => '',
            'source_file' => '',
            'line_number' => 0,
            'column_number' => 0,
            'disposition' => 'report',
            'user_agent' => '',
            'client_ip' => '',
            'seen_at' => current_time('mysql'),
        );
        $violation = wp_parse_args($violation, $defaults);

        $hash = self::report_hash($violation['directive'], $violation['blocked_uri'], $violation['document_uri']);
        $table = self::table_name();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $result = $wpdb->query($wpdb->prepare(
            "INSERT INTO {$table}
                (report_hash, severity, directive, blocked_uri, document_uri, source_file,
                 line_number, column_number, disposition, user_agent, client_ip,
                 hit_count, first_seen, last_seen)
             VALUES (%s, %s, %s, %s, %s, %s, %d, %d, %s, %s, %s, 1, %s, %s)
             ON DUPLICATE KEY UPDATE
                hit_count = hit_count + 1,
                last_seen = VALUES(last_seen),
                severity = VALUES(severity),
                disposition = VALUES(disposition)",
            $hash,
            $violation['severity'],
            substr($violation['directive'], 0, 64),
            $violation['blocked_uri'],
            $violation['document_uri'],
            $violation['source_file'],
            (int) $violation['line_number'],
            (int) $violation['column_number'],
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
    private function build_where($args) {
        global $wpdb;

        $where = array('1=1');

        if (!empty($args['severity'])) {
            $where[] = $wpdb->prepare('severity = %s', $args['severity']);
        }

        if (!empty($args['directive'])) {
            $where[] = $wpdb->prepare('directive = %s', $args['directive']);
        }

        if (!empty($args['search'])) {
            $like = '%' . $wpdb->esc_like($args['search']) . '%';
            $where[] = $wpdb->prepare('(blocked_uri LIKE %s OR document_uri LIKE %s OR source_file LIKE %s)', $like, $like, $like);
        }

        if (!empty($args['since'])) {
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
    public function get_violations($args = array()) {
        global $wpdb;

        $defaults = array(
            'orderby' => 'last_seen',
            'order' => 'DESC',
            'per_page' => 20,
            'paged' => 1,
        );
        $args = wp_parse_args($args, $defaults);

        $allowed_orderby = array('severity', 'directive', 'hit_count', 'last_seen', 'first_seen', 'id');
        $orderby = in_array($args['orderby'], $allowed_orderby, true) ? $args['orderby'] : 'last_seen';
        $order = strtoupper($args['order']) === 'ASC' ? 'ASC' : 'DESC';

        $per_page = max(1, (int) $args['per_page']);
        $offset = (max(1, (int) $args['paged']) - 1) * $per_page;

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
    public function count_violations($args = array()) {
        global $wpdb;

        $table = self::table_name();
        $where = $this->build_where($args);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table} WHERE {$where}");
    }

    /**
     * Delete violations by id.
     *
     * @param int[] $ids
     * @return int Rows deleted.
     */
    public function delete_violations($ids) {
        global $wpdb;

        $ids = array_filter(array_map('intval', (array) $ids));
        if (empty($ids)) {
            return 0;
        }

        $table = self::table_name();
        $placeholders = implode(',', array_fill(0, count($ids), '%d'));

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
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
    public function prune($retention_days) {
        global $wpdb;

        $cutoff = gmdate('Y-m-d H:i:s', time() - ((int) $retention_days * DAY_IN_SECONDS));
        $table = self::table_name();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        return (int) $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE last_seen < %s", $cutoff));
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
     * Get aggregate statistics for the last N days.
     *
     * @param int $days
     * @return array
     */
    public function get_stats($days = 7) {
        global $wpdb;

        $table = self::table_name();
        $since = gmdate('Y-m-d H:i:s', time() - ((int) $days * DAY_IN_SECONDS));

        $stats = array(
            'total_hits' => 0,
            'unique_patterns' => 0,
            'by_severity' => array('low' => 0, 'medium' => 0, 'high' => 0),
            'top_blocked' => array(),
            'by_day' => array(),
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $totals = $wpdb->get_row($wpdb->prepare(
            "SELECT COALESCE(SUM(hit_count), 0) AS hits, COUNT(*) AS patterns FROM {$table} WHERE last_seen >= %s",
            $since
        ), ARRAY_A);

        if ($totals) {
            $stats['total_hits'] = (int) $totals['hits'];
            $stats['unique_patterns'] = (int) $totals['patterns'];
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $severities = $wpdb->get_results($wpdb->prepare(
            "SELECT severity, SUM(hit_count) AS hits FROM {$table} WHERE last_seen >= %s GROUP BY severity",
            $since
        ), ARRAY_A);

        foreach ((array) $severities as $row) {
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
        foreach ((array) $daily as $row) {
            $by_day[$row['day']] = (int) $row['hits'];
        }

        for ($i = $days - 1; $i >= 0; $i--) {
            $day = gmdate('Y-m-d', time() - ($i * DAY_IN_SECONDS));
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
    public function migrate_legacy_logs($logger) {
        $imported = 0;

        foreach ($logger->get_log_files() as $file) {
            foreach ($logger->read_log_entries($file) as $entry) {
                if (!isset($entry['report_data']['csp-report'])) {
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
                    'disposition' => isset($report['disposition']) ? $report['disposition'] : 'report',
                    'user_agent' => isset($entry['user_agent']) ? $entry['user_agent'] : '',
                    'client_ip' => isset($entry['ip_address']) ? $entry['ip_address'] : '',
                    'seen_at' => isset($entry['timestamp']) ? $entry['timestamp'] : current_time('mysql'),
                ));

                $imported++;
            }
        }

        return $imported;
    }
}
