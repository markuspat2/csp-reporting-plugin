# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.1.0] - 2026-07-14

Tuning pass driven by the first live deployment.

### Fixed
- Deduplication was defeated by per-request query strings (scanner tokens,
  `?ver=` cache-busters): one violation pattern created a new row per
  crawled URL. Hashes are now computed on URLs normalized to
  scheme://host/path, and the upgrade migration merges existing duplicate
  rows (hit counts summed, first/last-seen widened).

### Changed
- **Client IP addresses are no longer stored by default.** IPs are personal
  data; a new "Store Client IP Addresses" setting re-enables recording.
  Rate limiting is unaffected.

### Added
- **"By Source" rollup view** on the Violations tab: one row per blocked
  origin + directive with reports, affected pages, worst severity, and an
  in-policy status — plus a bulk **Allow Selected Sources** action that
  writes the checked origins straight into the policy.
- Indexed `blocked_origin` column powering the rollup and status checks.
- Policy-builder presets for reCAPTCHA, Jetpack/WordPress.com, UserWay,
  Userback, Cloudflare Insights, and jsDelivr.
- JSON export now includes `blocked_origin` and emits numeric fields as
  numbers instead of strings.

## [2.0.0] - 2026-07-12

### Fixed
- Report endpoint never worked reliably: hooks were registered from inside
  the `init` callback at the same priority, which WordPress skips, so the
  rewrite rule powering `/csp-report-endpoint/` was never added. The endpoint
  is now a REST route and needs no rewrite rules.
- CSP headers were emitted from `wp_head`/`admin_head`, after output had
  started, so `header()` calls were dropped with "headers already sent"
  warnings. Headers are now sent on `send_headers` (and optionally
  `admin_init` for wp-admin).
- Severity assessment could never classify inline/eval violations: browsers
  report `blocked-uri: "inline"` / `"eval"`, not `"unsafe-inline"` /
  `"unsafe-eval"`.
- The admin template inlined a script duplicating `admin.js`, so every
  button action (clear logs, view, download) fired twice.
- Log files were pretty-printed JSON split by a dash separator that the
  plugin's own parsers could not reliably re-read. File logs are now NDJSON
  (one JSON object per line); the legacy format is still readable.

### Security
- The anonymous GET handler on the report endpoint disclosed the server's
  filesystem log path; testing is now an authenticated admin action.
- Removed the `csp_debug_rewrite` debug endpoint that echoed the raw
  request URI.
- The report endpoint is rate limited per IP (default 30/minute) and
  site-wide (default 5000/day), and payloads are capped at 32 KB.
- Client IPs are read from `REMOTE_ADDR` only; proxy headers are opt-in via
  the `csp_reporting_trusted_ip_headers` filter (they were previously
  trusted from any client and trivially spoofable).
- CSV exports guard against spreadsheet formula injection.

### Added
- Violations are stored in a dedicated `wp_csp_violations` table with
  deduplication: identical violations increment a counter instead of adding
  rows. Legacy log files are imported once on upgrade.
- Violations admin screen: sortable/filterable list table with severity
  badges, search, bulk delete, and CSV/JSON export.
- Structured policy builder with per-directive editing, live header
  preview, and presets (Google Fonts, Analytics, Tag Manager, YouTube).
- Delivery modes: Report-Only, Enforce, or Enforce + Test (dual header).
- One-click "Allow this source" on violation rows.
- Ignore patterns drop browser-extension and other noise before storage.
- Email digests (daily/weekly), immediate high-severity alerts, and
  Slack-compatible webhook notifications.
- Dashboard widget with a 7-day sparkline and top blocked sources.
- Modern Reporting API support: `Reporting-Endpoints` header, `report-to`
  directive, and `application/reports+json` batch payloads.
- WP-CLI commands: `wp csp status`, `wp csp policy get/set`,
  `wp csp violations list/clear`, `wp csp test-report`.
- Multisite: per-site policies plus a network admin overview of per-site
  violation counts.
- Extension hooks (previously documented but unimplemented):
  `csp_policy_directives`, `csp_report_data`, `csp_violation_logged`.
- `uninstall.php` cleanup, PHPCS (WordPress-Extra) configuration, PHPUnit
  suite, and GitHub Actions CI.

### Changed
- Report endpoint moved from `/csp-report-endpoint/` to
  `/wp-json/csp-reporting/v1/report`.
- File logging is now optional (off by default); the database is the
  primary store.
- The always-on admin notice was replaced by a dismissible notice shown
  only for new high-severity violations.

## [1.0.0]

- Initial release: report-only CSP header, file-based logging, admin
  settings page.
