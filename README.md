# CSP Reporting Plugin

Content Security Policy (CSP) headers with violation reporting, logging, and
analysis for WordPress. Built for agencies and teams managing CSPs across
many sites: low-noise reporting, a structured policy editor, notifications,
and WP-CLI automation.

> **New to the plugin or to CSP?** Start with the user guides in
> [`docs/`](docs/README.md): [Getting Started](docs/getting-started.md),
> [Understanding CSP](docs/understanding-csp.md), and
> [Crafting Your Policy](docs/crafting-your-policy.md). This README is the
> developer/reference companion.

## Features

- **Nonce mode for `script-src`** — adds a per-request `'nonce-…'` (and
  optionally `'strict-dynamic'`) to the enforced header, the report-only test
  header, or both, and stamps the nonce on every script WordPress prints. Run
  it on the Enforce + Test test policy first to inventory every inline script
  that still needs work, then enforce. Requires WordPress 6.4+; front end only.
- **Report-Only and Enforce modes** — start in Report-Only, tune the policy
  from real violation data, then flip to Enforce. A dual mode enforces the
  current policy while report-only testing a stricter draft.
- **Structured policy builder** — edit each directive's sources in the
  admin UI with a live header preview and presets for common services
  (Google Fonts, Google Analytics, Tag Manager, YouTube, reCAPTCHA,
  Jetpack/WordPress.com, UserWay, Userback, Cloudflare Insights, jsDelivr).
- **Database-backed violation storage** — violations land in a dedicated
  table, deduplicated by directive + blocked URI + page (query strings and
  cache-busters ignored) with hit counters and first/last-seen timestamps.
  Inline scripts are split per script (by code sample or line), and the code
  sample browsers send for `'report-sample'` is stored.
- **Inline inventory** — inline violations are labelled as script blocks
  (fixable with a nonce) or event handlers (need a code change), with the
  blocked code sample in the list and in exports.
- **Violations screen** — sortable, filterable, searchable list table with
  severity badges, bulk delete, and one-click **"Allow this source"** that
  adds a blocked origin to the right directive. Only plain origins
  (`scheme://host[:port]`) are ever offered or written to the policy, so a
  forged report can't smuggle a keyword like `'unsafe-inline'` in.
- **"By Source" rollup** — one row per blocked origin + directive with an
  in-policy status column and a bulk **Allow Selected Sources** action:
  review everything the policy blocked and fix the policy in one step.
- **Noise controls** — ignore patterns drop browser-extension and other
  junk reports before storage; per-IP and site-wide rate limits protect the
  endpoint from floods.
- **Notifications** — daily/weekly email digests, immediate high-severity
  alerts (throttled), and Slack-compatible webhooks (sent with
  `wp_safe_remote_post()`, so private and link-local addresses are refused).
- **Dashboard widget** — 7-day violation sparkline and top blocked sources.
- **Modern + legacy reporting** — sends `report-uri`, `report-to`, and
  `Reporting-Endpoints`, and accepts both `application/csp-report` and
  Reporting API (`application/reports+json`) batch payloads.
- **WP-CLI** — automate status checks, policy edits, and violation triage
  across a fleet of sites.
- **Multisite** — per-site policies with a network admin overview. Raw log
  files live in one shared directory, so viewing, downloading, or clearing
  them requires a network admin; uninstall cleans every site.
- **Export** — download filtered violations as CSV or JSON for client
  reports.

## Requirements

- WordPress 5.9 or higher (nonce mode requires **WordPress 6.4** or higher;
  below that its settings are disabled)
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
   report-only testing the stricter draft in the Test Policy box. Turn on
   **Nonce Mode** for the report-only header to get a per-script inventory of
   inline code to fix, then enable it on the enforced header. See
   [Crafting Your Policy](docs/crafting-your-policy.md#tightening-further-removing-unsafe-inline).

## Settings reference

| Setting | Default | Description |
| --- | --- | --- |
| Enable CSP Reporting | on | Master switch for sending CSP headers. |
| Delivery Mode | Report-Only | Report-Only, Enforce, or Enforce + Test. |
| Nonce Mode (script-src) | off | Per header: add a per-request nonce to the **report-only** header (the test policy in Enforce + Test, or the main policy in Report-Only) and/or the **enforced** header, plus optional `'strict-dynamic'`. Stamps every WordPress-printed script. Requires WordPress 6.4+; never applies to wp-admin. Enforcing it blocks every inline script without the nonce. |
| Report Samples | off | Add `'report-sample'` to `script-src` on every header sent so reports include the first 40 characters of blocked code. Doesn't change what is blocked; samples are page code and are stored and exported. |
| Policy Directives | sensible baseline | Per-directive source lists. |
| Apply to Admin Pages | off | Also send the header on wp-admin. |
| Log Retention (Days) | 30 | Violations and log files older than this are pruned daily. |
| Max Log File Size | 10 MB | Rotation threshold for optional file logs. |
| Raw File Logging | off | Also write NDJSON logs to `wp-content/csp-reports/` (or `CSP_REPORTING_LOG_DIR`). The directory is shared by every site on a multisite network, so there only network admins can view, download, or clear the files. On nginx, see [Raw logs on nginx](#raw-logs-on-nginx). |
| Rate Limit | 30/min/IP | Reports accepted per IP per minute (0 disables). |
| Ignore Patterns | extension noise | Substrings that drop matching reports. |
| Store Client IP Addresses | off | Record reporter IPs with violations, in both the database and raw file logs. Off by default — IPs are personal data (GDPR) and aren't needed for policy tuning; rate limiting works regardless. |
| Enable Admin Notices | on | Dismissible notice for new high-severity violations. |
| Purge Logs on Uninstall | off | Also delete the raw log files when the plugin is uninstalled. Settings and the violations table are always removed. |
| Notifications | off | Email digests, immediate alerts, webhook URL. |

## WP-CLI

```
wp csp status                                  # mode, endpoint, 7-day stats
wp csp policy get [--format=json]              # current directives
wp csp policy set script-src "'self' https://cdn.example.com"
wp csp nonce get                               # nonce mode settings
wp csp nonce set report-only on                # enforce | report-only | strict-dynamic | report-sample
wp csp violations list [--severity=high] [--format=csv] [--limit=100]
wp csp violations clear [--yes]
wp csp test-report                             # exercise the pipeline
```

## Hooks and filters

### Filters

- `csp_policy_directives( array $directives, string $context )` — modify the
  directive => sources map before the header is built. `$context` is
  `enforce` or `report-only`. Runs before nonce mode adds its nonce,
  `'strict-dynamic'`, and `'report-sample'` sources, so rebuilding
  `script-src` here can't drop them.
- `csp_reporting_nonce( string $nonce )` — override the per-request nonce
  (called once per request). For edge setups where a CDN worker swaps a
  fixed placeholder for a fresh nonce in both header and HTML. Values that
  aren't valid CSP base64/base64url are ignored.
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

### Template functions

For themes and plugins that print their own `<script>` tags (WordPress's
script API is stamped automatically in nonce mode):

- `csp_nonce()` — the current request's nonce value.
- `csp_nonce_attr()` — an escaped `nonce="…"` attribute:
  `<script <?php echo csp_nonce_attr(); ?>>…</script>`.

Both always return a value, even with nonce mode off, so templates can stamp
unconditionally.

## Nonce mode notes

- **WordPress 6.4+ only.** 6.4 is the first release that prints every
  `WP_Scripts` tag (enqueued, inline before/after, `wp_localize_script` data,
  translations) through `wp_script_attributes` / `wp_inline_script_attributes`.
  On older versions the settings are disabled and ignored.
- **Front end only.** wp-admin headers never carry a nonce and admin scripts
  are never stamped, even with "Apply to Admin Pages" on.
- **No blanket output stamping.** Only scripts printed through WordPress's
  script API get the nonce. Hard-coded tags show up as violations and are
  fixed with `csp_nonce_attr()`, so injected scripts are never blessed.
- **No `script-src`?** It's created from a copy of `default-src` (the nonce is
  never added to `default-src`, which `style-src` also falls back to). With
  neither directive, `script-src` contains only the nonce.
- **Full-page caches** store the nonce with the page, so it's shared until the
  cache expires. Make sure the cache stores headers with the body. See
  [Nonces and full-page caching](docs/crafting-your-policy.md#nonces-and-full-page-caching)
  for the trade-offs.

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
- **Nonce mode: every WordPress script reported as blocked** — the header's
  nonce doesn't match the page's. Usually a cache serving stored HTML with a
  freshly generated header (or vice versa). Compare the `'nonce-…'` in
  `curl -sI` output with `nonce="…"` in the page source.

## Data storage

- Violations: `{$wpdb->prefix}csp_violations` table (schema version 3 adds
  the `script_sample` column; existing rows are kept as-is on upgrade). Schema
  upgrades run automatically on the first request after an update — front end
  or admin — and only one request performs them.
- Optional raw logs: `wp-content/csp-reports/csp-reports-<date>-<secret>.log`
  (NDJSON, rotated at the configured size). The 24-character per-site secret
  in the name makes the files unguessable; the directory also gets a
  deny-all `.htaccess` (Apache 2.2 and 2.4) and an `index.php`. Files written
  with the old predictable names are renamed on the first admin visit or
  daily cleanup after updating.
- Retention: both stores are pruned daily after the configured number of
  days.
- Uninstall: options, scheduled events, and the table are always removed —
  on every site of a multisite network; log files are removed only if "Purge
  Logs on Uninstall" is enabled.

### Raw logs on nginx

nginx ignores `.htaccess`, so on nginx (SpinupWP, and WP Engine's front end)
the only built-in protection is the random secret in each file name. Raw file
logging is off by default; if you turn it on, add one of these:

- **Block the directory** in the server config. On SpinupWP, put this in an
  include under the site's `server` configuration directory:

  ```nginx
  location ^~ /wp-content/csp-reports/ {
      deny all;
  }
  ```

- **Move the logs outside the web root** with a constant in `wp-config.php`
  (the directory must be writable by PHP; on WP Engine, the `_wpeprivate`
  folder in the site root is not web-accessible):

  ```php
  define( 'CSP_REPORTING_LOG_DIR', '/path/outside/webroot/csp-reports/' );
  ```

The violations database, which the admin screens use, never involves these
files.

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
