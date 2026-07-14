# CSP Reporting Plugin

Content Security Policy (CSP) headers with violation reporting, logging, and
analysis for WordPress. Built for agencies and teams managing CSPs across
many sites: low-noise reporting, a structured policy editor, notifications,
and WP-CLI automation.

## Features

- **Report-Only and Enforce modes** — start in Report-Only, tune the policy
  from real violation data, then flip to Enforce. A dual mode enforces the
  current policy while report-only testing a stricter draft.
- **Structured policy builder** — edit each directive's sources in the
  admin UI with a live header preview and presets for common services
  (Google Fonts, Analytics, Tag Manager, YouTube).
- **Database-backed violation storage** — violations land in a dedicated
  table, deduplicated by directive + blocked URI + page (query strings and
  cache-busters ignored) with hit counters and first/last-seen timestamps.
- **Violations screen** — sortable, filterable, searchable list table with
  severity badges, bulk delete, and one-click **"Allow this source"** that
  adds a blocked origin to the right directive.
- **"By Source" rollup** — one row per blocked origin + directive with an
  in-policy status column and a bulk **Allow Selected Sources** action:
  review everything the policy blocked and fix the policy in one step.
- **Noise controls** — ignore patterns drop browser-extension and other
  junk reports before storage; per-IP and site-wide rate limits protect the
  endpoint from floods.
- **Notifications** — daily/weekly email digests, immediate high-severity
  alerts (throttled), and Slack-compatible webhooks.
- **Dashboard widget** — 7-day violation sparkline and top blocked sources.
- **Modern + legacy reporting** — sends `report-uri`, `report-to`, and
  `Reporting-Endpoints`, and accepts both `application/csp-report` and
  Reporting API (`application/reports+json`) batch payloads.
- **WP-CLI** — automate status checks, policy edits, and violation triage
  across a fleet of sites.
- **Multisite** — per-site policies with a network admin overview.
- **Export** — download filtered violations as CSV or JSON for client
  reports.

## Requirements

- WordPress 5.9 or higher
- PHP 7.4 or higher

## Installation

1. Upload the plugin files to `/wp-content/plugins/csp-reporting-plugin/`.
2. Activate the plugin through the **Plugins** screen.
3. Go to **Settings → CSP Reporting** to configure the policy.

## How it works

1. The plugin sends your policy as a `Content-Security-Policy-Report-Only`
   (or `Content-Security-Policy`) header on frontend responses, with
   `report-uri`/`report-to` pointing at the plugin's REST endpoint.
2. Browsers POST violation reports to
   `/wp-json/csp-reporting/v1/report`.
3. Reports are validated, rate limited, filtered against your ignore
   patterns, classified by severity, and stored deduplicated in the
   `wp_csp_violations` table.
4. You review violations under **Settings → CSP Reporting → Violations**,
   allow legitimate sources with one click, and tighten the policy until
   it's clean — then switch the mode to **Enforce**.

## Recommended tuning workflow

1. Start in **Report-Only** mode with the default policy.
2. Let it collect violations for a few days; the digest email summarizes
   activity.
3. Open **Violations → By Source**, check every origin that belongs on the
   site, and click **Allow Selected Sources**. Add ignore patterns for
   noise; use presets in the policy builder for common services.
4. When new violations dry up, switch to **Enforce**.
5. To tighten further (e.g. removing `'unsafe-inline'`), use
   **Enforce + Test** mode: keep enforcing the known-good policy while
   report-only testing the stricter draft in the Test Policy box.

## Settings reference

| Setting | Default | Description |
| --- | --- | --- |
| Enable CSP Reporting | on | Master switch for sending CSP headers. |
| Delivery Mode | Report-Only | Report-Only, Enforce, or Enforce + Test. |
| Policy Directives | sensible baseline | Per-directive source lists. |
| Apply to Admin Pages | off | Also send the header on wp-admin. |
| Log Retention (Days) | 30 | Violations and log files older than this are pruned daily. |
| Max Log File Size | 10 MB | Rotation threshold for optional file logs. |
| Raw File Logging | off | Also write NDJSON logs to `wp-content/csp-reports/`. |
| Rate Limit | 30/min/IP | Reports accepted per IP per minute (0 disables). |
| Ignore Patterns | extension noise | Substrings that drop matching reports. |
| Store Client IP Addresses | off | Record reporter IPs with violations. Off by default — IPs are personal data (GDPR) and aren't needed for policy tuning; rate limiting works regardless. |
| Enable Admin Notices | on | Dismissible notice for new high-severity violations. |
| Purge Logs on Uninstall | off | Delete all data when the plugin is uninstalled. |
| Notifications | off | Email digests, immediate alerts, webhook URL. |

## WP-CLI

```
wp csp status                                  # mode, endpoint, 7-day stats
wp csp policy get [--format=json]              # current directives
wp csp policy set script-src "'self' https://cdn.example.com"
wp csp violations list [--severity=high] [--format=csv] [--limit=100]
wp csp violations clear [--yes]
wp csp test-report                             # exercise the pipeline
```

## Hooks and filters

### Filters

- `csp_policy_directives( array $directives, string $context )` — modify the
  directive => sources map before the header is built. `$context` is
  `enforce` or `report-only`.
- `csp_report_data( array $report )` — modify (or return a falsy value to
  discard) an enriched report before it is stored.
- `csp_reporting_ignore_patterns( string[] $patterns )` — adjust the ignore
  patterns.
- `csp_reporting_rate_limit_per_minute( int $limit )` /
  `csp_reporting_rate_limit_per_day( int $limit )` — tune endpoint rate
  limits (0 disables).
- `csp_reporting_trusted_ip_headers( string[] $headers )` — `$_SERVER` keys
  allowed to supply the client IP when behind a trusted proxy, e.g.
  `HTTP_CF_CONNECTING_IP`. Only `REMOTE_ADDR` is trusted by default.
- `csp_reporting_max_alerts_per_day( int $max )` — cap on immediate
  high-severity alert emails.

### Actions

- `csp_violation_logged( array $report, string $severity )` — fires after a
  violation is recorded.
- `csp_cleanup_logs` — daily cron event that prunes old data.
- `csp_send_digest` — daily cron event that sends the digest.

## The report endpoint

`POST /wp-json/csp-reporting/v1/report`

- Accepts single `application/csp-report` objects and Reporting API
  (`application/reports+json`) batches.
- Unauthenticated by necessity (browsers send reports without credentials),
  protected by payload size caps (32 KB) and rate limits.
- Returns `204` on success, `400` for malformed reports, `413` for oversized
  payloads, and `429` when rate limited.

Verify it from a shell:

```bash
curl -i -X POST https://example.com/wp-json/csp-reporting/v1/report \
  -H 'Content-Type: application/csp-report' \
  -d '{"csp-report":{"document-uri":"https://example.com/","violated-directive":"script-src","blocked-uri":"https://evil.example.net/x.js"}}'
```

## Troubleshooting

- **No header on responses** — full-page caches and CDNs can strip or cache
  headers; check `curl -sI https://example.com/ | grep -i security`. Make
  sure another plugin or the server config isn't also setting CSP.
- **No reports arriving** — use the **Send Test Report** button (Settings →
  CSP Reporting) to verify the pipeline, then the `curl` command above to
  verify the endpoint from outside.
- **Reports flooding in** — add ignore patterns for the noisy source, or
  lower the rate limit. Violations deduplicate, so a single pattern only
  ever occupies one row.
- **Behind Cloudflare or a proxy** — client IPs will all be the proxy's
  unless you opt in via `csp_reporting_trusted_ip_headers`.

## Data storage

- Violations: `{$wpdb->prefix}csp_violations` table.
- Optional raw logs: `wp-content/csp-reports/*.log` (NDJSON, protected by
  `.htaccess`, rotated at the configured size).
- Retention: both stores are pruned daily after the configured number of
  days.
- Uninstall: options and the table are always removed; logs are removed only
  if "Purge Logs on Uninstall" is enabled.

## Development

```bash
composer install
composer lint    # php -l over the codebase
composer phpcs   # WordPress-Extra coding standards
composer test    # PHPUnit unit suite (no WordPress install needed)
```

CI runs the same three steps on PHP 7.4, 8.1, and 8.3.

## License

GPL v2 or later.
