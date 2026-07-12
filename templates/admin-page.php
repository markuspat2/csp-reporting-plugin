<?php
/**
 * Admin Page Template
 * 
 * Template for the CSP Reporting admin settings page
 */

if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap csp-admin-page">
    <h1><?php _e('CSP Reporting Settings', 'csp-reporting'); ?></h1>

    <?php $this->render_tabs('settings'); ?>

    <?php settings_errors(); ?>
    
    <div class="csp-admin-content">
        <div class="csp-main-content">
            <form method="post" action="options.php">
                <?php
                settings_fields('csp_reporting_options');
                do_settings_sections('csp-reporting');
                submit_button();
                ?>
            </form>
        </div>
        
        <div class="csp-sidebar">
            <div class="csp-widget">
                <h3><?php _e('Plugin Status', 'csp-reporting'); ?></h3>
                <div class="csp-status">
                    <div class="status-item">
                        <span class="status-label"><?php _e('CSP Reporting:', 'csp-reporting'); ?></span>
                        <span class="status-value <?php echo !empty($options['csp_enabled']) ? 'csp-status-enabled' : 'csp-status-disabled'; ?>">
                            <?php echo !empty($options['csp_enabled']) ? __('Enabled', 'csp-reporting') : __('Disabled', 'csp-reporting'); ?>
                        </span>
                    </div>
                    <div class="status-item">
                        <span class="status-label"><?php _e('Endpoint URL:', 'csp-reporting'); ?></span>
                        <span class="status-value"><?php echo esc_url(CSP_Utils::get_report_endpoint_url()); ?></span>
                    </div>
                </div>
            </div>
            
            <div class="csp-widget">
                <h3><?php _e('Violations (Last 7 Days)', 'csp-reporting'); ?></h3>
                <div class="csp-stats">
                    <div class="stat-item">
                        <span class="stat-label"><?php _e('Total Reports:', 'csp-reporting'); ?></span>
                        <span class="stat-value"><?php echo esc_html(number_format_i18n($db_stats['total_hits'])); ?></span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label"><?php _e('Unique Patterns:', 'csp-reporting'); ?></span>
                        <span class="stat-value"><?php echo esc_html(number_format_i18n($db_stats['unique_patterns'])); ?></span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label"><?php _e('High Severity:', 'csp-reporting'); ?></span>
                        <span class="stat-value"><?php echo esc_html(number_format_i18n($db_stats['by_severity']['high'])); ?></span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label"><?php _e('Medium Severity:', 'csp-reporting'); ?></span>
                        <span class="stat-value"><?php echo esc_html(number_format_i18n($db_stats['by_severity']['medium'])); ?></span>
                    </div>
                </div>
                <p>
                    <a href="<?php echo esc_url(add_query_arg(array('page' => 'csp-reporting', 'tab' => 'violations'), admin_url('options-general.php'))); ?>" class="button button-secondary">
                        <?php _e('View All Violations', 'csp-reporting'); ?>
                    </a>
                </p>
            </div>

            <?php if (!empty($options['file_logging_enabled'])): ?>
            <div class="csp-widget">
                <h3><?php _e('Log Files', 'csp-reporting'); ?></h3>
                <div class="csp-stats">
                    <div class="stat-item">
                        <span class="stat-label"><?php _e('Total Files:', 'csp-reporting'); ?></span>
                        <span class="stat-value"><?php echo esc_html($log_stats['total_files']); ?></span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label"><?php _e('Total Size:', 'csp-reporting'); ?></span>
                        <span class="stat-value"><?php echo esc_html($log_stats['total_size_formatted']); ?></span>
                    </div>
                </div>
            </div>
            <?php endif; ?>

            <?php if (!empty($log_files)): ?>
            <div class="csp-widget">
                <h3><?php _e('Log Files', 'csp-reporting'); ?></h3>
                <div class="csp-log-files">
                    <?php foreach (array_slice($log_files, 0, 10) as $file): ?>
                    <div class="log-file-item">
                        <span class="file-name"><?php echo esc_html(basename($file)); ?></span>
                        <div class="file-actions">
                            <button type="button" class="button button-small view-log" data-file="<?php echo esc_attr($file); ?>">
                                <?php _e('View', 'csp-reporting'); ?>
                            </button>
                            <button type="button" class="button button-small download-log" data-file="<?php echo esc_attr($file); ?>">
                                <?php _e('Download', 'csp-reporting'); ?>
                            </button>
                        </div>
                    </div>
                    <?php endforeach; ?>
                    
                    <?php if (count($log_files) > 10): ?>
                    <p class="more-files">
                        <?php printf(__('... and %d more files', 'csp-reporting'), count($log_files) - 10); ?>
                    </p>
                    <?php endif; ?>
                </div>
                
                <div class="log-actions">
                    <button type="button" class="button button-secondary" id="clear-logs">
                        <?php _e('Clear All Logs', 'csp-reporting'); ?>
                    </button>
                </div>
            </div>
            <?php endif; ?>
            
            <div class="csp-widget">
                <h3><?php _e('Quick Actions', 'csp-reporting'); ?></h3>
                <div class="quick-actions">
                    <button type="button" class="button button-secondary" id="send-test-report">
                        <?php _e('Send Test Report', 'csp-reporting'); ?>
                    </button>
                    <button type="button" class="button button-secondary" id="refresh-stats">
                        <?php _e('Refresh Statistics', 'csp-reporting'); ?>
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Log Viewer Modal -->
    <div id="log-viewer-modal" class="csp-modal" style="display: none;">
        <div class="csp-modal-content">
            <div class="csp-modal-header">
                <h3><?php _e('Log File Viewer', 'csp-reporting'); ?></h3>
                <span class="csp-modal-close">&times;</span>
            </div>
            <div class="csp-modal-body">
                <pre id="log-content"></pre>
            </div>
            <div class="csp-modal-footer">
                <button type="button" class="button button-primary" id="download-current-log">
                    <?php _e('Download', 'csp-reporting'); ?>
                </button>
                <button type="button" class="button button-secondary csp-modal-close">
                    <?php _e('Close', 'csp-reporting'); ?>
                </button>
            </div>
        </div>
    </div>
</div>



