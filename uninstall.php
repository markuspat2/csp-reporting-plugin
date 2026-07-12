<?php
/**
 * Uninstall handler for CSP Reporting Plugin.
 *
 * Removes options, notifications, cron events, the violations table, and
 * (if opted in) the log directory.
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$csp_options = get_option('csp_reporting_options', array());
$csp_purge_logs = !empty($csp_options['purge_logs_on_uninstall']);

delete_option('csp_reporting_options');
delete_option('csp_admin_notifications');
delete_option('csp_reporting_rewrite_version'); // Legacy 1.x marker.

wp_clear_scheduled_hook('csp_cleanup_logs');

global $wpdb;
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}csp_violations"); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery

if ($csp_purge_logs) {
    $csp_log_dir = WP_CONTENT_DIR . '/csp-reports/';

    if (is_dir($csp_log_dir)) {
        foreach ((array) glob($csp_log_dir . '{*.log,.htaccess,index.php}', GLOB_BRACE) as $csp_file) {
            if (is_file($csp_file)) {
                unlink($csp_file);
            }
        }

        rmdir($csp_log_dir);
    }
}
