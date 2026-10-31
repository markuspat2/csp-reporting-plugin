<?php
/**
 * Uninstall handler for CSP Reporting Plugin.
 *
 * Removes options, notifications, cron events, the violations table, and
 * (if opted in) the log directory.
 */

if ( ! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$csp_options    = get_option('csp_reporting_options', array());
$csp_purge_logs = ! empty($csp_options['purge_logs_on_uninstall']);

/**
 * Remove one site's options, cron events, and violations table.
 */
function csp_reporting_uninstall_site() {
    global $wpdb;

    delete_option('csp_reporting_options');
    delete_option('csp_admin_notifications');
    delete_option('csp_reporting_db_version');
    delete_option('csp_reporting_logs_migrated');
    delete_option('csp_reporting_rewrite_version'); // Legacy 1.x marker.

    wp_clear_scheduled_hook('csp_cleanup_logs');
    wp_clear_scheduled_hook('csp_send_digest');

    $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}csp_violations"); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
}

// On multisite every site has its own options and table (network
// activation creates them on each site), not just the current one.
if (is_multisite()) {
    foreach (get_sites(array( 'fields' => 'ids', 'number' => 0 )) as $csp_site_id) {
        switch_to_blog($csp_site_id);
        csp_reporting_uninstall_site();
        restore_current_blog();
    }
} else {
    csp_reporting_uninstall_site();
}

if ($csp_purge_logs) {
    $csp_log_dir = WP_CONTENT_DIR . '/csp-reports/';

    if (is_dir($csp_log_dir)) {
        // No GLOB_BRACE: it is unavailable on some platforms (e.g. musl).
        $csp_files = array_merge(
            (array) glob($csp_log_dir . '*.log'),
            array( $csp_log_dir . '.htaccess', $csp_log_dir . 'index.php' )
        );

        foreach ($csp_files as $csp_file) {
            if (is_file($csp_file)) {
                unlink($csp_file);
            }
        }

        rmdir($csp_log_dir);
    }
}
