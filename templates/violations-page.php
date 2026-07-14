<?php
/**
 * Violations Page Template
 *
 * Renders the CSP violations list table. Included from
 * CSP_Admin::render_violations_page(), so $this and $list_table are in scope.
 */

if ( ! defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap csp-admin-page">
    <h1><?php esc_html_e('CSP Violations', 'csp-reporting'); ?></h1>

    <?php $this->render_tabs('violations'); ?>

    <?php settings_errors('csp_reporting'); ?>

    <?php $csp_views_base = admin_url('options-general.php?page=csp-reporting&tab=violations'); ?>
    <ul class="subsubsub">
        <li><a href="<?php echo esc_url($csp_views_base); ?>" class="current"><?php esc_html_e('All Violations', 'csp-reporting'); ?></a> |</li>
        <li><a href="<?php echo esc_url(add_query_arg('view', 'source', $csp_views_base)); ?>"><?php esc_html_e('By Source', 'csp-reporting'); ?></a></li>
    </ul>
    <div class="clear"></div>

    <?php
    $export_base = wp_nonce_url(admin_url('admin-post.php?action=csp_export_violations'), 'csp_export_violations');
    foreach ($list_table->get_filter_args() as $key => $value) {
        $export_base = add_query_arg($key === 'search' ? 's' : $key, rawurlencode($value), $export_base);
    }
    ?>
    <p class="csp-export-actions">
        <a href="<?php echo esc_url(add_query_arg('format', 'csv', $export_base)); ?>" class="button button-secondary">
            <?php esc_html_e('Export CSV', 'csp-reporting'); ?>
        </a>
        <a href="<?php echo esc_url(add_query_arg('format', 'json', $export_base)); ?>" class="button button-secondary">
            <?php esc_html_e('Export JSON', 'csp-reporting'); ?>
        </a>
    </p>

    <form method="get">
        <input type="hidden" name="page" value="csp-reporting" />
        <input type="hidden" name="tab" value="violations" />
        <?php
        $list_table->search_box(__('Search violations', 'csp-reporting'), 'csp-violation');
        $list_table->display();
        ?>
    </form>
</div>
