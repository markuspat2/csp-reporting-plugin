<?php
/**
 * Violations Page Template
 *
 * Renders the CSP violations list table. Included from
 * CSP_Admin::render_violations_page(), so $this and $list_table are in scope.
 */

if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap csp-admin-page">
    <h1><?php _e('CSP Violations', 'csp-reporting'); ?></h1>

    <?php $this->render_tabs('violations'); ?>

    <?php settings_errors('csp_reporting'); ?>

    <form method="get">
        <input type="hidden" name="page" value="csp-reporting" />
        <input type="hidden" name="tab" value="violations" />
        <?php
        $list_table->search_box(__('Search violations', 'csp-reporting'), 'csp-violation');
        $list_table->display();
        ?>
    </form>
</div>
