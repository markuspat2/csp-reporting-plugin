<?php
/**
 * Violations "By Source" Rollup Template
 *
 * One row per blocked origin + directive with in-policy status and a bulk
 * "Allow selected sources" action. Included from
 * CSP_Admin::render_by_source_page(), so $this, $rows, and
 * $sourceless_count are in scope.
 */

if ( ! defined('ABSPATH')) {
    exit;
}

$csp_views_base = admin_url('options-general.php?page=csp-reporting&tab=violations');
?>

<div class="wrap csp-admin-page">
    <h1><?php esc_html_e('CSP Violations', 'csp-reporting'); ?></h1>

    <?php $this->render_tabs('violations'); ?>

    <?php settings_errors('csp_reporting'); ?>

    <ul class="subsubsub">
        <li><a href="<?php echo esc_url($csp_views_base); ?>"><?php esc_html_e('All Violations', 'csp-reporting'); ?></a> |</li>
        <li><a href="<?php echo esc_url(add_query_arg('view', 'source', $csp_views_base)); ?>" class="current"><?php esc_html_e('By Source', 'csp-reporting'); ?></a></li>
    </ul>
    <div class="clear"></div>

    <p class="description">
        <?php esc_html_e('Every external source your policy blocked, rolled up across pages. Select the ones that belong on the site and allow them in one step — the policy updates immediately.', 'csp-reporting'); ?>
    </p>

    <?php if (empty($rows)) : ?>
        <p><?php esc_html_e('No blocked external sources recorded yet.', 'csp-reporting'); ?></p>
    <?php else : ?>
    <form method="post">
        <?php wp_nonce_field('csp_bulk_allow'); ?>
        <table class="widefat striped csp-by-source-table">
            <thead>
                <tr>
                    <td class="check-column"><input type="checkbox" id="csp-select-all-sources" /></td>
                    <th><?php esc_html_e('Blocked Origin', 'csp-reporting'); ?></th>
                    <th><?php esc_html_e('Directive', 'csp-reporting'); ?></th>
                    <th><?php esc_html_e('Status', 'csp-reporting'); ?></th>
                    <th><?php esc_html_e('Severity', 'csp-reporting'); ?></th>
                    <th><?php esc_html_e('Reports', 'csp-reporting'); ?></th>
                    <th><?php esc_html_e('Pages', 'csp-reporting'); ?></th>
                    <th><?php esc_html_e('Last Seen', 'csp-reporting'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($rows as $row) : ?>
                <tr>
                    <th class="check-column">
                        <?php if ( ! $row['allowed']) : ?>
                        <input type="checkbox" name="sources[]"
                                value="<?php echo esc_attr($row['directive'] . '|' . $row['blocked_origin']); ?>" />
                        <?php endif; ?>
                    </th>
                    <td><code><?php echo esc_html($row['blocked_origin']); ?></code></td>
                    <td><code><?php echo esc_html($row['directive']); ?></code></td>
                    <td>
                        <?php if ($row['allowed']) : ?>
                            <span class="csp-status-badge csp-status-allowed"><?php esc_html_e('Allowed', 'csp-reporting'); ?></span>
                        <?php else : ?>
                            <span class="csp-status-badge csp-status-missing"><?php esc_html_e('Not in policy', 'csp-reporting'); ?></span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <span class="csp-severity csp-severity-<?php echo esc_attr($row['severity']); ?>">
                            <?php echo esc_html(ucfirst($row['severity'])); ?>
                        </span>
                    </td>
                    <td><?php echo esc_html(number_format_i18n( (int) $row['hits'])); ?></td>
                    <td><?php echo esc_html(number_format_i18n( (int) $row['pages'])); ?></td>
                    <td><?php echo esc_html(mysql2date(get_option('date_format') . ' ' . get_option('time_format'), $row['last_seen'])); ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <p class="submit">
            <button type="submit" name="csp_allow_sources" value="1" class="button button-primary">
                <?php esc_html_e('Allow Selected Sources', 'csp-reporting'); ?>
            </button>
            <a href="<?php echo esc_url(admin_url('options-general.php?page=csp-reporting')); ?>" class="button button-secondary">
                <?php esc_html_e('Review Policy', 'csp-reporting'); ?>
            </a>
        </p>
    </form>
    <?php endif; ?>

    <?php if ($sourceless_count > 0) : ?>
    <p class="description">
        <?php
        echo esc_html(sprintf(
            /* translators: %d: count of inline/eval violation patterns */
            _n(
                '%d violation pattern has no allowable source (inline scripts, eval, or data: URIs). These need a policy change — e.g. a nonce/hash strategy or an unsafe-* keyword — not a new origin.',
                '%d violation patterns have no allowable source (inline scripts, eval, or data: URIs). These need a policy change — e.g. a nonce/hash strategy or an unsafe-* keyword — not a new origin.',
                $sourceless_count,
                'csp-reporting'
            ),
            $sourceless_count
        ));
        ?>
        <a href="<?php echo esc_url($csp_views_base); ?>"><?php esc_html_e('See them in All Violations.', 'csp-reporting'); ?></a>
    </p>
    <?php endif; ?>
</div>
