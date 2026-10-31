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
7. Tighten       Use nonce mode in Enforce + Test to retire 'unsafe-inline'.
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
> (e.g. keeping `'unsafe-inline'` for now, or moving to nonce mode), not a new
> source. See [tightening further](#tightening-further-removing-unsafe-inline).

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
policy the most, and security scanners flag them (along with host allowlists,
which attackers can often bypass). The fix the scanners ask for is **nonces with
`'strict-dynamic'`**, and the plugin's **nonce mode** does the heavy lifting.
If you're new to nonces, read
[Nonces and `'strict-dynamic'`](understanding-csp.md#nonces-and-strict-dynamic)
first.

The approach: turn nonce mode on for a **report-only test policy** while your
current policy stays enforced, let real traffic list every inline script that
still lacks the nonce, fix them, and only then turn nonce mode on for the
enforced policy. Nothing breaks along the way.

> **Requirements and scope.** Nonce mode needs **WordPress 6.4 or newer** (the
> first release that lets plugins stamp every script WordPress prints; on older
> versions the settings are disabled). It covers `script-src` only and applies
> to the **front end only**: wp-admin never gets a nonce, even with "Apply to
> Admin Pages" on. Inline *styles* keep relying on `'unsafe-inline'` in
> `style-src`.

### Step 1 — Turn on nonce mode for the test policy

1. Settings → **Delivery Mode** → **Enforce + Test**. Your current policy keeps
   being enforced exactly as before.
2. In the **Test Policy** box, paste your current policy (or leave the box
   empty to test the main policy as-is). You can leave `'unsafe-inline'` and
   your allowed hosts in it — see the note below.
3. Under **Nonce Mode (script-src)**, tick **Report-only header** and **Also
   add `'strict-dynamic'`**. Leave **Enforced header** unticked for now.
4. Tick **Report Samples** so each report includes the first 40 characters of
   the blocked code. It makes the next steps much faster.
5. Save, then check a page:
   - The `Content-Security-Policy-Report-Only` header's `script-src` now ends
     with `'nonce-…' 'strict-dynamic'`
     (`curl -sI https://yoursite.com/ | grep -i report-only`).
   - In the page source, every script WordPress printed carries a matching
     `nonce="…"`. That covers enqueued files, inline scripts added with
     `wp_add_inline_script()`, and `wp_localize_script()` data.

> **Why keep `'unsafe-inline'` and hosts in the policy?** Browsers that support
> nonces ignore `'unsafe-inline'` as soon as a nonce is present, and with
> `'strict-dynamic'` they also ignore host sources and `'self'`. Older browsers
> that don't understand nonces fall back to them. So they're harmless to modern
> browsers and keep old ones working. The plugin never removes them for you.

From WP-CLI: `wp csp nonce set report-only on`,
`wp csp nonce set strict-dynamic on`, `wp csp nonce set report-sample on`.

### Step 2 — Collect the inline inventory

Let it run on real traffic for a few days, then open **Violations → All
Violations** and filter by directive:

- **`script-src-elem`, shown as "Inline script block"**: a `<script>` tag
  without the nonce. Fixable with a nonce (step 3).
- **`script-src-attr`, shown as "Inline event handler"**: an `onclick=`,
  `onload=` and so on. **No nonce can fix these**; they need a code change
  (step 4).
- **"eval() / dynamic code"**: code passed to `eval()` or `new Function()`.
  The fix is in the script that calls it, shown as the source file.

Each distinct inline script gets its own row with its page, line number and
code sample, so the list is your to-do list. External scripts don't show up
here: with `'strict-dynamic'`, anything a nonced script loads is trusted
automatically.

### Step 3 — Fix hard-coded scripts

WordPress-printed scripts are stamped automatically. What's left is code that
prints its own `<script>` tag, usually a theme template or a plugin.

- **Preferred:** move the code into WordPress's script API, which stamps it for
  you: `wp_enqueue_script()` for files, `wp_add_inline_script()` for snippets.
- **Quick fix in a template:** add the nonce attribute with the plugin's
  helper:

  ```php
  <script <?php echo csp_nonce_attr(); ?>>
      window.dataLayer = window.dataLayer || [];
  </script>
  ```

  `csp_nonce()` returns the raw value if you need it elsewhere. Both helpers
  are safe to call even when nonce mode is off.

- **Google Tag Manager snippet:** stamp both the `<script>` in `<head>` and
  anything else your theme hard-codes the same way. The `<noscript>` iframe
  needs nothing.
- **A plugin you don't control:** check for a setting or a newer version that
  uses the script API, or ask its author. Until then it stays on your list.

### Step 4 — Rewrite inline event handlers

Handlers can't carry a nonce, so they have to move into a script:

```html
<!-- Before -->
<button onclick="openMenu()">Menu</button>

<!-- After -->
<button class="js-open-menu">Menu</button>
```

```js
// In an enqueued script file:
document.querySelectorAll('.js-open-menu').forEach(function (el) {
    el.addEventListener('click', openMenu);
});
```

The same goes for `javascript:` links (`href="javascript:…"`).

### Step 5 — Review Google Tag Manager custom HTML tags

GTM is where most surprises hide, because its tags aren't in your theme.

- With `'strict-dynamic'`, scripts that the nonced `gtm.js` inserts are
  trusted, so most tags — including many Custom HTML tags, whose scripts GTM
  re-creates itself — keep working.
- **If Custom HTML tags still show up as violations** (or you run nonce mode
  without `'strict-dynamic'`), pass them the nonce: in GTM, create a **DOM
  Element** variable that reads the `nonce` attribute of your GTM `<script>`
  tag, and add `nonce="{{your variable}}"` to each `<script>` in those tags.
- Custom HTML that uses inline event handlers or `document.write()` needs to be
  rewritten, as in step 4.
- Violations whose source file is `gtm.js` point at these tags. Use GTM's
  preview mode to find which tag fires on the reported page.

### Step 6 — Enforce nonce mode

When the test header has stopped producing new inline violations:

1. Under **Nonce Mode**, tick **Enforced header** (keep `'strict-dynamic'`).
2. Keep **Enforce + Test** running for a while so anything new still shows up.

> **Warning:** once nonce mode is on for the enforced header, **every inline
> script without the nonce is blocked**, including any hard-coded script or
> event handler you missed. That's the point, but only flip it once the test
> policy is quiet.

At that point inline injection is blocked in every modern browser. Some
scanners read the policy text literally and keep flagging `'unsafe-inline'` or
host allowlists that browsers are in fact ignoring. To satisfy them, you can
then edit `script-src` down to `'self'`; the plugin adds the nonce and
`'strict-dynamic'`. That gives up the fallback for browsers too old to
understand nonces, which are now very rare.

### Nonces and full-page caching

A nonce is generated by PHP for each page render. If a full-page cache (WP
Engine, SpinupWP's FastCGI cache, Cloudflare, a caching plugin) stores the page,
it stores the nonce with it, and every visitor gets **the same nonce** until
that cache entry expires.

- **That still works.** The cached header and the cached page carry the same
  nonce, so nothing breaks. But the nonce is no longer per-request, which
  weakens it: someone who has seen the page can learn the nonce. Your options:
  - **Accept a per-cache nonce.** This is still a big improvement over
    `'unsafe-inline'`, and short cache lifetimes limit exposure. It's the
    practical default for most sites.
  - **Exclude pages from the cache.** Use this for pages where it matters most
    (checkout, account, forms), using your host's or cache plugin's
    exclusions.
  - **Replace the nonce at the edge.** Have a CDN worker (for example a
    Cloudflare Worker) swap a fixed placeholder for a fresh value in both the
    header and the HTML on every response. Return the placeholder from the
    `csp_reporting_nonce` filter so the cached copy contains it (see the
    [README](../README.md)).
- **Check that your cache stores headers.** Some caches save only the HTML and
  serve it without the headers PHP sent. Others serve the cached HTML while a
  fresh header is generated. In the first case the page has no CSP at all (true
  for any CSP header, not just nonces). In the second case, the header's nonce
  won't match the page's, and **an enforced policy will block every script**.
  This is one more reason to run nonce mode in the report-only test first:
  mismatches show up as a flood of violations for scripts WordPress printed,
  not as a broken site.

The plugin doesn't disable or bypass caching; choose the trade-off that fits
the site.

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
