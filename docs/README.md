# CSP Reporting Plugin – API Documentation

This document describes all public APIs, classes, functions, endpoints, admin actions, and options exposed by the plugin. It also includes concrete usage examples.

## Table of contents

- Overview
- Constants
- Classes and methods
  - CSP_Reporting_Plugin
  - CSP_Admin
  - CSP_Logger
  - CSP_Reporter
- Global functions
- HTTP endpoints
- Admin AJAX actions
- Options and configuration
- Examples

---

## Overview

The plugin adds a CSP report-only header to WordPress pages and exposes an endpoint that receives and logs CSP violation reports to files in `wp-content/csp-reports/`. An admin UI under Settings › CSP Reporting lets you configure policies and inspect logs.

---

## Constants

- `CSP_REPORTING_VERSION` (string): Current plugin version.
- `CSP_REPORTING_PLUGIN_DIR` (string): Absolute filesystem path to the plugin directory.
- `CSP_REPORTING_PLUGIN_URL` (string): Absolute URL to the plugin directory.
- `CSP_REPORTING_LOG_DIR` (string): Absolute filesystem path for log storage (defaults to `WP_CONTENT_DIR . '/csp-reports/'`).

---

## Classes and methods

### CSP_Reporting_Plugin

Singleton that wires the plugin into WordPress and coordinates admin and reporting components.

- `public static function get_instance(): self`
  - Returns the singleton instance and initializes hooks on first call.
- `public function init(): void`
  - Instantiates `CSP_Logger`, `CSP_Admin`, and `CSP_Reporter` and registers all runtime hooks.
- `public function load_textdomain(): void`
  - Loads translations from `/languages`.
- `public function activate(): void`
  - Creates log directory, stores default options, schedules `csp_cleanup_logs`, and flushes rewrite rules.
- `public function deactivate(): void`
  - Clears the scheduled `csp_cleanup_logs` event.
- `public function add_csp_headers(): void`
  - Sends `Content-Security-Policy-Report-Only` header using the saved policy and report endpoint URL.
- `public function add_csp_endpoint(): void`
  - Registers rewrite rule and query var for `/csp-report-endpoint/`.
- `public function maybe_flush_rewrite_rules(): void`
  - Flushes rewrite rules when the plugin version changes.
- `public function handle_csp_endpoint(): void`
  - Handles incoming requests to the CSP report endpoint (rewrite or direct URL) and delegates to `CSP_Reporter::handle_report()`.
- `public function handle_csp_report(): void`
  - Handles AJAX `csp_report` and delegates to `CSP_Reporter::handle_report()`.
- `public function show_admin_notices(): void`
  - Delegates to `CSP_Admin::show_admin_notices()` for dashboard notices.
- `public function debug_rewrite_rules(): void`
  - Outputs rewrite and request diagnostics when `?csp_debug_rewrite=1` is present for admins.

Key hooks registered:

- `init`, `plugins_loaded`, `wp_head`, `admin_head`, `template_redirect`
- `wp_ajax_csp_report`, `wp_ajax_nopriv_csp_report`

Usage example:

```php
// Force initialization (normally handled by plugin bootstrap)
CSP_Reporting_Plugin::get_instance();
```

### CSP_Admin

Provides the Settings › CSP Reporting page and AJAX endpoints for log operations.

- `public function add_admin_menu(): void`
- `public function register_settings(): void`
- `public function enqueue_admin_scripts(string $hook): void`
- `public function admin_page(): void`
- `public function sanitize_options(array $input): array`
- `public function csp_enabled_callback(): void`
- `public function csp_policy_callback(): void`
- `public function log_retention_callback(): void`
- `public function log_max_size_callback(): void`
- `public function admin_notices_callback(): void`
- `public function download_log_file(): void` (AJAX, admin only)
- `public function clear_log_files(): void` (AJAX, admin only)
- `public function get_log_content(): void` (AJAX, admin only)
- `public function show_admin_notices(): void`

Notes:

- All AJAX methods verify a nonce (`csp_admin_nonce`) and `manage_options` capability.
- Log file paths are validated to be within `CSP_REPORTING_LOG_DIR`.

### CSP_Logger

Writes violation reports to JSON-formatted log files and provides utilities.

- `public function __construct()`
- `public function log_violation(array $report_data): bool`
  - Validates and writes a single violation entry. Rotates files when size exceeds the configured limit.
- `public function get_log_files(): array`
- `public function get_log_contents(string $file_path, int $limit = 100): string|false`
- `public function clean_old_logs(int $retention_days = 30): int`
- `public function get_log_statistics(): array`

Example: manually log a violation (for testing)

```php
$logger = new CSP_Logger();
$fake = [
  'csp-report' => [
    'document-uri' => home_url('/'),
    'violated-directive' => 'script-src',
    'effective-directive' => 'script-src-elem',
    'original-policy' => "default-src 'self'",
    'disposition' => 'report',
    'blocked-uri' => 'data:text/javascript',
    'status-code' => 200,
  ],
];
$logger->log_violation($fake);
```

### CSP_Reporter

Parses and validates incoming reports, enriches them, logs via `CSP_Logger`, and provides statistics.

- `public function __construct()`
- `public function handle_report(): void`
  - GET returns JSON describing endpoint health and environment.
  - POST expects a JSON body with a `csp-report` object; returns HTTP 204 on success, JSON error on failure.
- `public function get_violation_statistics(int $days = 7): array`

Example: load recent statistics (e.g., from custom admin code)

```php
$reporter = new CSP_Reporter();
$stats = $reporter->get_violation_statistics(7);
// $stats['total_violations'], $stats['by_severity'], etc.
```

---

## Global functions

- `function csp_cleanup_old_logs(): void`
  - Deletes log files older than the configured retention period. Bound to the `csp_cleanup_logs` scheduled action.

---

## HTTP endpoints

### CSP report endpoint

- Path: `/csp-report-endpoint/`
- Methods:
  - GET: Health/diagnostic JSON
  - POST: Accepts CSP violation reports

Request (POST) body schema (minimum required fields):

```json
{
  "csp-report": {
    "document-uri": "https://example.com/page",
    "violated-directive": "script-src",
    "effective-directive": "script-src-elem",
    "original-policy": "default-src 'self'",
    "disposition": "report",
    "blocked-uri": "data:text/javascript",
    "status-code": 200
  }
}
```

Responses:

- 204 No Content on success
- 400 JSON error body for invalid or missing data

Notes:

- The endpoint is also registered for AJAX as `csp_report` for both authenticated and unauthenticated requests.

---

## Admin AJAX actions

All endpoints require a valid nonce `csp_admin_nonce` and `manage_options` capability:

- `action=csp_download_log` (POST)
  - Inputs: `file_path`
  - Response: file download
- `action=csp_clear_logs` (POST)
  - Response: `{ success: true, data: { message } }`
- `action=csp_get_log_content` (POST)
  - Inputs: `file_path`
  - Response: `{ success: true, data: { content } }`

---

## Options and configuration

All options are stored under `csp_reporting_options`:

- `csp_enabled` (bool): Enable sending CSP report-only headers. Default: `true`.
- `csp_policy` (string): CSP directives string. Default included in activation routine.
- `log_retention_days` (int): Days to keep logs. Default: `30`.
- `log_max_size` (int): Max single log file size in bytes. Default: `10485760` (10 MB).
- `enable_admin_notices` (bool): Show admin notices when violations are present. Default: `true`.

Other internal options:

- `csp_reporting_rewrite_version` (string): Used to trigger rewrite flush.
- `csp_admin_notifications` (array): Ring buffer of recent notifications (up to 50).

---

## Examples

### Verify endpoint health (GET)

```bash
curl -sS "https://your-site.example/csp-report-endpoint/" | jq .
```

### Send a sample violation (POST)

```bash
curl -sS -X POST \
  -H "Content-Type: application/csp-report" \
  -d '{
    "csp-report": {
      "document-uri": "https://your-site.example/",
      "violated-directive": "script-src",
      "effective-directive": "script-src-elem",
      "original-policy": "default-src \'self\'",
      "disposition": "report",
      "blocked-uri": "data:text/javascript",
      "status-code": 200
    }
  }' \
  -i "https://your-site.example/csp-report-endpoint/"
```

Expected: `HTTP/1.1 204 No Content`.

### Programmatically fetch statistics

```php
$reporter = new CSP_Reporter();
$stats = $reporter->get_violation_statistics(30);
error_log('CSP total in last 30 days: ' . $stats['total_violations']);
```

### Hook into scheduled cleanup

```php
add_action('csp_cleanup_logs', function () {
  // Your additional cleanup or syncing logic
});
```

---

Notes and limitations

- Only the `csp_cleanup_logs` action is currently emitted by the plugin. Additional hooks referenced in the root README (`csp_violation_logged`, `csp_report_data`, `csp_policy_directives`) are not present in this version.

