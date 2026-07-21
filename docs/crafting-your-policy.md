# Crafting Your Policy

This is the heart of the plugin. You've [installed it](getting-started.md) and
it's been quietly logging in Report-Only mode. Now you'll turn that log of
"things the browser would have blocked" into a Content Security Policy that fits
your site exactly — and then switch it on.

The whole approach in one line: **let real traffic tell you what your site
needs, approve the legitimate parts, silence the noise, then enforce.**

---

## The workflow at a glance

```
1. Collect      Report-Only mode gathers real violations for a few days.
2. Review       Open Violations → By Source to see what got blocked, grouped.
3. Approve      "Allow" the sources that belong on your site.
4. Silence      Add ignore patterns for noise you don't control.
5. Repeat       Let it run again; the list should shrink toward zero.
6. Enforce      When new violations dry up, switch the mode to Enforce.
7. Tighten       Use Enforce + Test to safely remove 'unsafe-inline' later.
```

Steps 2–5 are a loop. You're not trying to get it perfect in one sitting — each
pass makes the policy fit a little better and the noise a little quieter.

---

## Step 1 — Collect

Leave the plugin in **Report-Only** mode and let it run on live traffic for a
few days. Real visitors load pages, embedded widgets, and third-party scripts
you might never hit yourself, and every block becomes a report.

If you've enabled the **email digest** (Settings → Notifications), you'll get a
summary of activity without having to check manually.

## Step 2 — Review what got blocked

Go to **Settings → CSP Reporting → Violations**. There are two views, linked at
the top:

- **All Violations** — every recorded violation, one row per unique pattern,
  with a hit counter and filters for severity and directive. Good for digging
  into specifics.
- **By Source** — the view you'll live in. It rolls everything up to **one row
  per blocked origin + directive**, showing how many reports and how many pages
  each affected, its worst severity, and — crucially — whether it's already
  **Allowed** or **Not in policy**.

### Reading severity

Each violation is rated so you know where to look first:

| Severity | What it usually means | Your reaction |
| --- | --- | --- |
| **High** | A serious pattern: a violation of `object-src`, `base-uri`, `form-action`, or `frame-ancestors`, or a script blocked from a dangerous scheme (`javascript:`, `data:`, `vbscript:`, `blob:`). | Look immediately. Could be an attack or a genuinely risky embed. |
| **Medium** | A script (`script-src`) blocked from an external host, or your own inline/eval scripts being caught. | Review — usually a legitimate third-party script you haven't approved yet. |
| **Low** | A blocked style, font, image, or background request. | Almost always benign. Approve or ignore. |

> **Why are my legit scripts flagged "medium"?** Because an unexpected script
> source deserves a look even when it turns out fine. In practice most mediums
> are third-party tools you simply haven't allowlisted yet — approving them (next
> step) makes them disappear.

## Step 3 — Approve the legitimate sources

For every source in the **By Source** view that genuinely belongs on your site,
you have two one-click options:

- On a single row, use the **Allow** action to add that origin to the correct
  directive.
- Or tick several rows and use **Allow Selected Sources** to add them all at
  once.

Either way, the plugin writes the origin into the right directive of your policy
for you — no hand-editing headers. The next time the page loads, that source is
allowed, and it stops generating violations.

You can also work from the **Settings** tab's policy builder directly. It has
one row per directive (as a text box you can edit) plus **preset buttons** for
common services — Google Fonts, Google Analytics, Tag Manager, YouTube,
reCAPTCHA, Jetpack/WordPress.com, UserWay, Userback, Cloudflare Insights, and
jsDelivr — that fill in the right origins in the right directives instantly. A
live preview shows the header you're building as you type.

> **What about inline/eval violations?** Some violations have no external origin
> to allow — blocked inline scripts, `eval`, or `data:` scripts. The By Source
> view lists these separately and notes that they need a *policy* decision
> (e.g. keeping `'unsafe-inline'` for now, or moving to a nonce/hash strategy),
> not a new source. See [tightening further](#tightening-further-removing-unsafe-inline).

## Step 4 — Silence the noise

Not every violation is about your site. Browser extensions, translation tools,
and injected content produce reports for things you don't control and can't fix.
The plugin ships with **Ignore Patterns** (Settings tab) pre-filled to drop the
most common offenders (`chrome-extension://`, `moz-extension://`, `about:blank`,
and similar).

If you see recurring noise from a source you'll never allow and never need to
see, add a pattern for it (one per line). Any report whose blocked URI or source
file contains that text is dropped before it's ever stored — keeping your logs
focused on decisions that actually matter.

## Step 5 — Repeat until quiet

Let the plugin run again for a day or two. With the legitimate sources approved
and the noise filtered, the stream of *new* violations should slow to a trickle
and then stop. When you go a few days with no new legitimate violations, your
policy fits your site — and you're ready to enforce.

---

## A worked example

Say a typical WordPress marketing site runs Jetpack, a reCAPTCHA contact form,
the UserWay accessibility widget, and loads a slider library from jsDelivr.
After a few days in Report-Only, the **By Source** view might look like this:

| Blocked origin | Directive | Severity | Status | What it is |
| --- | --- | --- | --- | --- |
| `https://cdn.userway.org` | `script-src` | Medium | Not in policy | Accessibility widget |
| `https://www.gstatic.com` | `script-src` | Medium | Not in policy | reCAPTCHA |
| `https://www.google.com` | `frame-src` | Low | Not in policy | reCAPTCHA challenge frame |
| `https://s0.wp.com` | `script-src` | Medium | Not in policy | Jetpack |
| `https://cdn.jsdelivr.net` | `script-src` | Medium | Not in policy | Slider library |
| `https://static.cloudflareinsights.com` | `script-src` | Medium | Not in policy | Cloudflare analytics |

Every one is legitimate. You'd:

1. Tick them all and click **Allow Selected Sources** (or click the matching
   **preset** buttons — reCAPTCHA, Jetpack/WordPress.com, UserWay, jsDelivr,
   Cloudflare Insights — which add the right origins across `script-src`,
   `frame-src`, `connect-src`, etc. in one go).
2. Add an ignore pattern if, say, a browser-extension source keeps appearing.
3. Save, then let it run another day. The list comes back empty — your policy now
   describes your real site.

## Step 6 — Enforce

Once new violations have dried up:

1. Settings → **Delivery Mode** → switch to **Enforce**.
2. Save.

The plugin now sends the enforcing header. Anything *not* in your policy is
actively blocked — which is exactly the protection you wanted, and safe to do
because you've already confirmed your real content is covered.

Keep the [admin notices](getting-started.md#recommended-first-settings) and/or
email digest on. If a future plugin update or new embed introduces a source your
policy doesn't cover, you'll still get a violation report (enforce mode reports
too), and you can allow it the same way.

---

## Tightening further: removing `'unsafe-inline'`

The default policy includes `'unsafe-inline'` and `'unsafe-eval'` on
`script-src` because many themes and plugins need them. They also weaken your
policy the most, so removing them is the highest-value improvement you can make —
but doing it carelessly can break your site. That's what **Enforce + Test** mode
is for.

1. Keep your working, known-good policy as the enforced one.
2. Settings → **Delivery Mode** → **Enforce + Test**.
3. In the **Test Policy** box, paste a stricter version of your policy — for
   example, the same policy but with `'unsafe-inline'`/`'unsafe-eval'` removed
   from `script-src`.
4. Save.

Now the browser **enforces your safe policy** (so nothing breaks) while
**report-only testing the stricter one**. Every inline script the stricter
policy would block shows up as a violation — a punch list of exactly what you'd
need to fix (usually by adding hashes/nonces or moving inline code into files)
before the stricter policy is safe to enforce. When the test policy stops
producing violations, promote it to your enforced policy.

This is an advanced step. It's completely optional — an enforced policy that
still allows inline scripts is already far better than no policy at all.

---

## Keeping it healthy over time

- **Dashboard widget** — the WordPress dashboard shows a 7-day violation
  sparkline and your top blocked sources at a glance.
- **Notifications** — daily/weekly email digests summarize activity; immediate
  alerts (throttled) fire on new high-severity violations; an optional
  Slack-compatible webhook posts the same content.
- **Export** — from the Violations tab, export the filtered list as **CSV** or
  **JSON** — useful for attaching a security summary to a client report.
- **Retention** — violations older than your retention window (default 30 days)
  are cleaned up automatically, so the store doesn't grow without bound.

## For developers: customizing the logic

Everything above is doable from the admin UI. If you need to go further, the
plugin exposes filters and actions — for example, `csp_report_data` lets you
rewrite or drop a report (including its severity) before it's stored, and
`csp_policy_directives` lets you modify the policy before the header is sent. The
full hook reference, the REST endpoint contract, and the WP-CLI commands are in
the [project README](../README.md).
