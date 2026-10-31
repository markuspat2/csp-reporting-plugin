# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.2.0] - Unreleased

Nonce mode: move `script-src` off `'unsafe-inline'` and host allowlists to
`'nonce-…' 'strict-dynamic'`, using Enforce + Test to inventory every inline
script that still needs work first.

### Added
- **Nonce mode for `script-src`** (requires WordPress 6.4+, front end only).
  It is set separately for the enforced header and the report-only header,
  so it can run on the Enforce + Test test policy alone. A per-request nonce
  is added to that header's `script-src`. If there is no `script-src`, one
  is created from a copy of `default-src`. Optionally `'strict-dynamic'` is
  added too. Existing `'unsafe-inline'` and host sources are kept as the
  fallback for older browsers.
- Every script WordPress prints gets the nonce through
  `wp_script_attributes` / `wp_inline_script_attributes`. That covers
  enqueued scripts, inline before/after scripts, `wp_localize_script` data,
  translations, script modules, and the import map. Nothing is stamped in
  wp-admin, and nothing is stamped by output buffering.
- Template helpers `csp_nonce()` and `csp_nonce_attr()` for hard-coded
  `<script>` tags, and a `csp_reporting_nonce` filter to override the value
  (e.g. an edge placeholder).
- **Report Samples** setting: adds `'report-sample'` to `script-src` on every
  header sent. Code samples from both report formats (`script-sample` and
  Reporting API `sample`) are stored, capped at 255 characters, shown in the
  Violations list, searchable, and included in CSV/JSON exports.
- Inline violations are labelled as inline script blocks (fixable with a
  nonce), inline event handlers (need a code change), or eval. The label is
  in the list, and exports carry it as an `inline_type` column.
- `wp csp nonce get|set` and nonce rows in `wp csp status`. Nonce mode in
  the sidebar status.
- The live header preview shows each header the mode sends, including
  `'nonce-{generated per request}'`.

### Changed
- Distinct inline scripts on one page are now separate violation rows. The
  dedup hash for inline/eval violations includes the source file and code
  sample (or line number when there is no sample). URL-based hashes are
  unchanged.
- The test policy and the enforced policy are built by one code path, so
  the test policy is now normalized the same way.
- The database schema check runs on every request (one option read), so
  reports that arrive before an admin page loads after an update are not
  lost.

### Database
- Schema version 3 adds a nullable `script_sample` column. Existing rows are
  not rewritten. Old per-page inline aggregate rows age out through
  retention.
- The upgrade runs under an atomic lock, so only one of many concurrent
  requests performs the `ALTER TABLE`, and the version is recorded only once
  the column exists, so a failed `ALTER` is retried.
- On tables still using 3-byte `utf8`, 4-byte characters (emoji) are
  stripped from samples instead of the whole report failing to store.

### Fixed
- Retention pruning, the digest and dashboard windows, the per-day sparkline,
  and the high-severity notice compared site-local `last_seen` values with
  UTC cutoffs, so they were off by the site's UTC offset (on a New York
  site a violation from 22 hours ago was missing from the "last 24 hours"
  digest and pruned early by a 1-day retention). Cutoffs are now local.
- Uninstall on multisite only cleaned the current site: every other site
  kept its options, violations table, and cron events. It now cleans each
  site, also clears the digest cron event and the schema/migration options,
  and no longer relies on `GLOB_BRACE` when purging logs.
- The release workflow interpolated the free-text `version` input into its
  shell script; it is now passed via the environment and must be `X.Y.Z`.
- The site-wide "per day" report cap and the immediate-alert cap renewed
  their expiry on every hit, so they never reset under steady traffic and
  acted as cumulative caps. They are now fixed windows (per minute, per UTC
  day).
- Log rotation replaced `.log` anywhere in the path, breaking for paths like
  `/var/www/my.logistics/`.

### Removed
- Every medium/high report was also written to a `csp_admin_notifications`
  option nothing reads, and to the PHP error log, an extra write per report
  and a flooded error log on busy sites. Both are gone (the admin notice
  comes from the violations table).
- The settings page no longer reads and decodes every log file to count
  entries it never displayed.
- Unused code: `CSP_Reporter::get_violation_statistics()`, and admin.js
  `initTooltips()` (which stripped the native tooltips from truncated URLs)
  and `debounce()`.

### Security
- **Stored XSS and policy injection from forged reports.** `parse_url()`
  accepts hosts containing spaces, quotes, `;` and markup, so a forged,
  unauthenticated report such as
  `blocked-uri: "https://cdn.example.com 'unsafe-inline'/x.js"` produced an
  "Allow" link that added `'unsafe-inline'` (or `*`) to the live policy, and a
  host containing `<img onerror=…>` ran script in wp-admin when the admin
  clicked "Allow". Origins taken from reports must now be a plain
  `scheme://host[:port]`, `add_source()` refuses anything else, and admin
  alerts are inserted as text.
- **Log file viewer/download read arbitrary files.** The path check compared
  a `realpath()` prefix: when `wp-content/csp-reports/` was missing it let any
  path through (including `wp-config.php`), and it accepted sibling
  directories. Only files the plugin itself lists as log files are served
  now.
- **Multisite:** the log directory is shared by every site, so a single
  site's administrator could read (or clear) all sites' logs — and, through
  the path bug, the network's `wp-config.php`. Raw log files now require
  `manage_network_options` on multisite, and 1.x logs are imported only into
  the main site's table instead of every site's.
- Raw file logs recorded visitor IPs even with "Store Client IP Addresses"
  off; they now follow the setting.
- Report fields of the wrong type (`"blocked-uri": ["x"]`) caused PHP fatal
  errors on the public endpoint; fields are now coerced to the expected
  types.
- Webhooks are sent with `wp_safe_remote_post()`, which refuses private and
  link-local addresses (e.g. cloud metadata endpoints).
- The CSV export's formula-injection guard also covers values starting with
  a tab or carriage return.
- **Raw log files were publicly downloadable on nginx.** They used predictable
  names (`csp-reports-2026-10-31.log`) and relied on an Apache-only
  `.htaccess`, so on nginx anyone could fetch them, including full page URLs
  (for example order keys in query strings) and, when enabled, visitor IPs.
  File names now include a 24-character per-site secret; existing files are
  renamed on the first admin visit or the daily cleanup; `.htaccess` uses both
  Apache 2.2 and 2.4 syntax and is written whenever the directory is created.
  `CSP_REPORTING_LOG_DIR` can now be defined in `wp-config.php` to keep logs
  outside the web root, and the README documents an nginx rule.
- **Rate limits could be bypassed with one request.** They counted requests,
  but a Reporting API batch carries 100+ reports in the 32 KB payload cap (one
  POST inserted 150 rows against a 30/minute limit). They now count reports.

## [2.1.0] - 2026-07-21

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

### Admin UI
- Policy directive sources are now wrapping textareas, so long values are
  fully visible instead of truncating in a single-line field.
- The Plugin Status endpoint URL wraps inside its box instead of overflowing.
- The All Violations and By Source tables use the full admin width.

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
