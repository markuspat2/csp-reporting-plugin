<?php
/**
 * PHPUnit bootstrap: minimal WordPress function stubs so the plugin's pure
 * logic (policy parsing, severity mapping, report validation, ignore
 * matching, dedup hashing) is testable without a WordPress install.
 */

define('ABSPATH', sys_get_temp_dir() . '/wp/');
define('WP_CONTENT_DIR', sys_get_temp_dir() . '/wp-content');
define('CSP_REPORTING_LOG_DIR', WP_CONTENT_DIR . '/csp-reports/');
define('CSP_REPORTING_VERSION', 'test');
define('MINUTE_IN_SECONDS', 60);
define('DAY_IN_SECONDS', 86400);

/**
 * In-memory option store the stubs read/write; tests may prime it.
 *
 * @var array
 */
$GLOBALS['csp_test_options'] = array();

function get_option($name, $default = false) {
    return isset($GLOBALS['csp_test_options'][$name]) ? $GLOBALS['csp_test_options'][$name] : $default;
}

function update_option($name, $value, $autoload = null) {
    $GLOBALS['csp_test_options'][$name] = $value;
    return true;
}

function add_option($name, $value) {
    if (!isset($GLOBALS['csp_test_options'][$name])) {
        $GLOBALS['csp_test_options'][$name] = $value;
    }
    return true;
}

function apply_filters($hook, $value) {
    return $value;
}

function do_action($hook, ...$args) {}
function add_action($hook, $callback, $priority = 10, $args = 1) {}
function add_filter($hook, $callback, $priority = 10, $args = 1) {}

function wp_parse_args($args, $defaults = array()) {
    return array_merge($defaults, (array) $args);
}

function wp_parse_url($url, $component = -1) {
    return parse_url($url, $component);
}

function wp_json_encode($data, $options = 0) {
    return json_encode($data, $options);
}

function current_time($type) {
    return date($type === 'mysql' ? 'Y-m-d H:i:s' : $type);
}

function home_url($path = '') {
    return 'https://example.test' . $path;
}

function rest_url($path = '') {
    return 'https://example.test/wp-json/' . ltrim($path, '/');
}

function __($text, $domain = null) {
    return $text;
}

function get_transient($key) {
    return isset($GLOBALS['csp_test_transients'][$key]) ? $GLOBALS['csp_test_transients'][$key] : false;
}

function set_transient($key, $value, $expiration = 0) {
    $GLOBALS['csp_test_transients'][$key] = $value;
    return true;
}

require_once dirname(__DIR__) . '/includes/class-csp-utils.php';
require_once dirname(__DIR__) . '/includes/class-csp-policy.php';
require_once dirname(__DIR__) . '/includes/class-csp-database.php';
require_once dirname(__DIR__) . '/includes/class-csp-logger.php';
require_once dirname(__DIR__) . '/includes/class-csp-reporter.php';
