<?php
/**
 * CSP Violations List Table
 *
 * WP_List_Table for browsing, filtering, and bulk-managing violations.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('WP_List_Table')) {
    require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

class CSP_Violations_List_Table extends WP_List_Table {

    /**
     * @var CSP_Database
     */
    private $database;

    /**
     * Constructor
     *
     * @param CSP_Database $database
     */
    public function __construct($database) {
        parent::__construct(array(
            'singular' => 'csp_violation',
            'plural' => 'csp_violations',
            'ajax' => false,
        ));

        $this->database = $database;
    }

    /**
     * Current filter args from the request.
     *
     * @return array
     */
    public function get_filter_args() {
        $args = array();

        if (!empty($_REQUEST['severity'])) {
            $args['severity'] = sanitize_key($_REQUEST['severity']);
        }

        if (!empty($_REQUEST['directive'])) {
            $args['directive'] = sanitize_text_field(wp_unslash($_REQUEST['directive']));
        }

        if (!empty($_REQUEST['s'])) {
            $args['search'] = sanitize_text_field(wp_unslash($_REQUEST['s']));
        }

        return $args;
    }

    public function get_columns() {
        return array(
            'cb' => '<input type="checkbox" />',
            'severity' => __('Severity', 'csp-reporting'),
            'directive' => __('Directive', 'csp-reporting'),
            'blocked_uri' => __('Blocked URI', 'csp-reporting'),
            'document_uri' => __('Page', 'csp-reporting'),
            'hit_count' => __('Count', 'csp-reporting'),
            'last_seen' => __('Last Seen', 'csp-reporting'),
        );
    }

    protected function get_sortable_columns() {
        return array(
            'severity' => array('severity', false),
            'directive' => array('directive', false),
            'hit_count' => array('hit_count', true),
            'last_seen' => array('last_seen', true),
        );
    }

    protected function get_bulk_actions() {
        return array(
            'delete' => __('Delete', 'csp-reporting'),
        );
    }

    /**
     * Severity / directive filter dropdowns above the table.
     *
     * @param string $which
     */
    protected function extra_tablenav($which) {
        if ($which !== 'top') {
            return;
        }

        $severity = isset($_REQUEST['severity']) ? sanitize_key($_REQUEST['severity']) : '';
        $directive = isset($_REQUEST['directive']) ? sanitize_text_field(wp_unslash($_REQUEST['directive'])) : '';
        ?>
        <div class="alignleft actions">
            <select name="severity">
                <option value=""><?php esc_html_e('All severities', 'csp-reporting'); ?></option>
                <?php foreach (array('high', 'medium', 'low') as $level) : ?>
                    <option value="<?php echo esc_attr($level); ?>" <?php selected($severity, $level); ?>>
                        <?php echo esc_html(ucfirst($level)); ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <select name="directive">
                <option value=""><?php esc_html_e('All directives', 'csp-reporting'); ?></option>
                <?php foreach ($this->database->get_distinct_directives() as $dir) : ?>
                    <option value="<?php echo esc_attr($dir); ?>" <?php selected($directive, $dir); ?>>
                        <?php echo esc_html($dir); ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <?php submit_button(__('Filter', 'csp-reporting'), '', 'filter_action', false); ?>
        </div>
        <?php
    }

    public function prepare_items() {
        $per_page = $this->get_items_per_page('csp_violations_per_page', 20);

        $args = $this->get_filter_args();
        $args['orderby'] = isset($_REQUEST['orderby']) ? sanitize_key($_REQUEST['orderby']) : 'last_seen';
        $args['order'] = isset($_REQUEST['order']) ? sanitize_key($_REQUEST['order']) : 'DESC';
        $args['per_page'] = $per_page;
        $args['paged'] = $this->get_pagenum();

        $total_items = $this->database->count_violations($args);

        $this->items = $this->database->get_violations($args);

        $this->_column_headers = array($this->get_columns(), array(), $this->get_sortable_columns());

        $this->set_pagination_args(array(
            'total_items' => $total_items,
            'per_page' => $per_page,
            'total_pages' => (int) ceil($total_items / $per_page),
        ));
    }

    protected function column_cb($item) {
        return sprintf('<input type="checkbox" name="violation_ids[]" value="%d" />', (int) $item['id']);
    }

    protected function column_severity($item) {
        $severity = $item['severity'];
        return sprintf(
            '<span class="csp-severity csp-severity-%s">%s</span>',
            esc_attr($severity),
            esc_html(ucfirst($severity))
        );
    }

    protected function column_directive($item) {
        return '<code>' . esc_html($item['directive']) . '</code>';
    }

    protected function column_blocked_uri($item) {
        $uri = $item['blocked_uri'];
        $display = strlen($uri) > 80 ? substr($uri, 0, 77) . '…' : $uri;

        $out = '<span title="' . esc_attr($uri) . '">' . esc_html($display !== '' ? $display : __('(inline)', 'csp-reporting')) . '</span>';

        if (!empty($item['source_file'])) {
            $out .= '<br /><small>' . esc_html(sprintf(
                /* translators: 1: source file, 2: line number */
                __('at %1$s:%2$d', 'csp-reporting'),
                $item['source_file'],
                (int) $item['line_number']
            )) . '</small>';
        }

        $actions = array();

        $directive = CSP_Policy::base_directive($item['directive']);
        $source = CSP_Policy::source_from_blocked_uri($item['blocked_uri']);

        if ($directive && $source) {
            $actions['allow'] = sprintf(
                '<a href="#" class="csp-allow-source" data-id="%d">%s</a>',
                (int) $item['id'],
                sprintf(
                    /* translators: 1: origin, 2: directive */
                    esc_html__('Allow %1$s in %2$s', 'csp-reporting'),
                    esc_html($source),
                    esc_html($directive)
                )
            );
        }

        return $out . $this->row_actions($actions);
    }

    protected function column_document_uri($item) {
        $uri = $item['document_uri'];
        $display = strlen($uri) > 60 ? substr($uri, 0, 57) . '…' : $uri;
        return '<span title="' . esc_attr($uri) . '">' . esc_html($display) . '</span>';
    }

    protected function column_hit_count($item) {
        return esc_html(number_format_i18n((int) $item['hit_count']));
    }

    protected function column_last_seen($item) {
        return esc_html(sprintf(
            /* translators: 1: last seen datetime, 2: first seen date */
            __('%1$s (first: %2$s)', 'csp-reporting'),
            mysql2date(get_option('date_format') . ' ' . get_option('time_format'), $item['last_seen']),
            mysql2date(get_option('date_format'), $item['first_seen'])
        ));
    }

    protected function column_default($item, $column_name) {
        return isset($item[$column_name]) ? esc_html($item[$column_name]) : '';
    }

    public function no_items() {
        esc_html_e('No CSP violations recorded. That either means your policy is clean, or the header is not being sent — use "Send Test Report" to verify the pipeline.', 'csp-reporting');
    }
}
