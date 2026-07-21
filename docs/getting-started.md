# Getting Started

This guide gets the plugin installed, sends its first violation report, and
leaves you in a safe **Report-Only** mode where nothing on your site can break.
Budget about ten minutes.

> **The one thing to know up front:** by default this plugin only *watches* and
> *reports*. It does not block anything on your site until you deliberately
> switch it to **Enforce** mode (covered in [Crafting Your Policy](crafting-your-policy.md)).
> So you can install it on a live site today without risk.

---

## 1. Install and activate

1. In WordPress admin, go to **Plugins → Add New → Upload Plugin**.
2. Upload the `csp-reporting-plugin.zip` file and click **Install Now**.
3. Click **Activate**.

On activation the plugin creates its settings, a database table to store
violations, and a daily cleanup task. Nothing is sent to your visitors' browsers
yet beyond a passive reporting header.

## 2. Open the settings

Go to **Settings → CSP Reporting**. You'll see two tabs:

- **Settings** — where you configure the policy and how the plugin behaves.
- **Violations** — where reported problems show up (empty for now).

At the top of the Settings tab, confirm:

- **Enable CSP Reporting** is checked.
- **Delivery Mode** is set to **Report-Only** (the default). Leave it here for
  now — this is the "watch, don't block" mode.

The sidebar shows your **Endpoint URL** (something like
`https://yoursite.com/wp-json/csp-reporting/v1/report`). That's where browsers
send violation reports. You don't need to do anything with it; it's shown for
reference.

## 3. Confirm the pipeline works

Before trusting the data, prove that reports actually arrive.

1. On the **Settings** tab sidebar, click **Send Test Report**.
2. Switch to the **Violations** tab.

You should see a new row appear. If it does, the full path — header sent →
browser reports → plugin stores it → you can see it — is working end to end.

> **Nothing showing up?** See [Troubleshooting](#troubleshooting) below.

## 4. Let it collect real data

Now just browse your own site normally for a few minutes — visit the homepage,
a blog post, a contact form, anything with embedded content (videos, maps,
chat widgets, analytics). Each time your browser blocks something your policy
doesn't yet allow, it quietly reports it, and a row appears under **Violations**.

Leave the plugin in Report-Only mode for at least a few days on a real site so
it captures the full range of pages and third-party services your visitors
actually load. The more traffic it sees, the more complete your picture.

When you're ready to turn that collected data into an actual security policy,
continue to [Crafting Your Policy](crafting-your-policy.md).

---

## Recommended first settings

The defaults are sensible, but these are worth a glance on the Settings tab:

| Setting | Suggested starting value | Why |
| --- | --- | --- |
| Delivery Mode | **Report-Only** | Watch without blocking while you learn what your site loads. |
| Enable Admin Notices | On | You'll get a heads-up in wp-admin when high-severity violations appear. |
| Log Retention (Days) | 30 | How long violations are kept before automatic cleanup. |
| Store Client IP Addresses | Off | IPs are personal data and aren't needed to build a policy. Leave off unless you have a specific reason. |
| Ignore Patterns | (defaults) | Pre-filled to drop common browser-extension noise so your logs stay meaningful. |

Optional, once you're comfortable:

- **Notifications** — turn on an email digest (daily or weekly) and/or immediate
  alerts for high-severity violations. There's also a Slack-compatible webhook
  field.
- **Apply to Admin Pages** — leave off unless you specifically want the policy
  on `/wp-admin` too.

---

## For developers

A few things beyond the admin UI, covered in full in the
[project README](../README.md):

- **Report endpoint:** `POST /wp-json/csp-reporting/v1/report`. Accepts both the
  legacy `application/csp-report` object and modern Reporting API
  (`application/reports+json`) batches. It's rate-limited and size-capped.
- **WP-CLI:** `wp csp status`, `wp csp policy get/set`,
  `wp csp violations list`, `wp csp test-report` — handy for scripting across
  multiple sites.
- **Multisite:** policies are per-site; a network admin overview shows per-site
  violation counts.

---

## Troubleshooting

**The test report worked, but real browsing produces no violations.**
That can be a *good* sign — it means nothing on the pages you visited was
blocked by the current policy. Try a page with more third-party content (an
embedded video, a map, a chat widget) to confirm reports still flow.

**Even the test report didn't appear.**
- Make sure **Enable CSP Reporting** is checked and you clicked **Save Changes**.
- A full-page cache or CDN can strip or cache response headers. Check that the
  header is present:
  ```bash
  curl -sI https://yoursite.com/ | grep -i content-security
  ```
  You should see a `Content-Security-Policy-Report-Only` header. If it's missing,
  a cache/CDN or another security plugin may be interfering.
- Confirm no other plugin or your server config is already setting a CSP header
  (two policies can conflict).

**All my visitors show the same IP, or no IP.**
IP storage is off by default (by design). If you enable it and sit behind
Cloudflare or another proxy, every report will show the proxy's IP unless you
opt specific forwarded headers in — see the developer README.

**I want to start over.**
On the Violations tab you can bulk-delete rows, or use
`wp csp violations clear`. Clearing violations doesn't change your policy.
