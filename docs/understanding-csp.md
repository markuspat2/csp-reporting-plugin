# Understanding Content Security Policy

Before you build a policy, it helps to understand what one *is*. This guide
explains Content Security Policy (CSP) in plain terms, then gets more precise
for readers who want the details. You don't need to memorize any of it — the
plugin does the mechanical work — but knowing the shape of the thing makes the
[policy-crafting workflow](crafting-your-policy.md) click.

---

## The one-paragraph version

A Content Security Policy is a list of rules your website sends to the visitor's
browser that says *"only load scripts, styles, images, fonts, and frames from
these specific places."* If the page then tries to load something from anywhere
else — often because malicious code was injected into your site — the browser
refuses. CSP is one of the most effective defenses against cross-site scripting
(XSS), where an attacker sneaks their JavaScript onto your page to steal data or
hijack sessions.

## Why it matters

Modern WordPress sites pull in a lot of third-party content: analytics, fonts,
embedded videos, chat widgets, maps, payment forms. Every one of those is a door.
If an attacker manages to inject a `<script>` tag — through a vulnerable plugin,
a compromised ad network, a bad form field — the browser will run it just like
your own code, because the browser can't tell the difference.

A CSP flips the default from *"run anything the page contains"* to *"only run
what the site owner explicitly approved."* Injected script from an unapproved
source simply doesn't execute. It's a safety net that catches whole categories
of attacks even when something else has already gone wrong.

## How the browser enforces it

Your server sends the policy as an HTTP response header. There are two versions:

- **`Content-Security-Policy`** — the **enforcing** header. The browser actively
  blocks anything the policy disallows.
- **`Content-Security-Policy-Report-Only`** — the **watching** header. The
  browser *doesn't* block anything; it just sends a report every time something
  *would have been* blocked.

This plugin starts with the Report-Only header so you can see exactly what your
policy would block **before** it blocks anything. That's the whole strategy:
watch first, enforce second.

---

## Anatomy of a policy

A policy is a series of **directives**, separated by semicolons. Each directive
names a type of content and lists the **sources** allowed for it:

```
default-src 'self'; script-src 'self' https://www.googletagmanager.com; img-src 'self' data: https:;
```

Read that as three rules:

- `default-src 'self'` — by default, only load things from my own domain.
- `script-src 'self' https://www.googletagmanager.com` — scripts may come from
  my domain *or* Google Tag Manager.
- `img-src 'self' data: https:` — images may come from my domain, inline
  `data:` URIs, or any HTTPS source.

### Directives you'll see most

| Directive | Controls | Typical example |
| --- | --- | --- |
| `default-src` | The fallback for anything not given its own rule. | `'self'` |
| `script-src` | JavaScript. **The security-critical one.** | `'self' https://www.googletagmanager.com` |
| `style-src` | Stylesheets and inline styles. | `'self' 'unsafe-inline'` |
| `img-src` | Images. | `'self' data: https:` |
| `font-src` | Web fonts. | `'self' https://fonts.gstatic.com` |
| `connect-src` | Background requests (`fetch`, XHR, WebSocket). | `'self' https://www.google-analytics.com` |
| `frame-src` | Embedded frames/iframes (videos, maps). | `https://www.youtube.com` |
| `form-action` | Where forms may submit. | `'self'` |
| `base-uri` | The `<base>` tag (an XSS escalation vector). | `'self'` |
| `object-src` | Legacy plugins (Flash, applets). | `'none'` |
| `frame-ancestors` | Who may embed *your* site (clickjacking defense). | `'self'` |

### Common source values

| Source | Means |
| --- | --- |
| `'self'` | Your own domain (same origin). |
| `'none'` | Nothing at all — block this content type entirely. |
| `https://example.com` | That exact origin. |
| `https:` | Any origin, as long as it's HTTPS. |
| `data:` | Inline `data:` URIs (common for small images and fonts). |
| `'unsafe-inline'` | Allow inline `<script>`/`<style>` and `style="..."` attributes. |
| `'unsafe-eval'` | Allow `eval()` and similar dynamic code execution. |

> **About the "unsafe" values:** `'unsafe-inline'` and `'unsafe-eval'` on
> `script-src` significantly weaken your policy — they're the exact things an
> attacker wants. Many themes and plugins rely on inline scripts, so you may
> need them at first, but removing them is the single biggest security win you
> can work toward. The plugin's **Enforce + Test** mode
> ([see the workflow](crafting-your-policy.md#tightening-further-removing-unsafe-inline))
> is built specifically for testing their removal safely.

---

## Report-Only vs. Enforce (and a third option)

This plugin offers three delivery modes:

- **Report-Only** — sends the watching header. Nothing is blocked; everything is
  logged. **Start here.**
- **Enforce** — sends the enforcing header. The policy is live and actively
  blocks disallowed content.
- **Enforce + Test** — sends *both* headers at once: it enforces your known-good
  policy while report-only testing a stricter draft. This lets you trial a
  tighter policy on live traffic without any risk of breaking the site. It's the
  safe way to iterate once you're already enforcing.

The intended lifecycle is simple:

```
Report-Only  →  (tune using the logs)  →  Enforce  →  (Enforce + Test to tighten further)
```

## What a violation report contains

When the browser blocks (or would block) something, it sends the plugin a report
with the useful details:

- **`document-uri`** — the page it happened on.
- **`violated-directive`** — which rule was broken (e.g. `script-src-elem`).
- **`blocked-uri`** — what got blocked (a URL, or a keyword like `inline`/`eval`).
- **`source-file`, `line-number`** — where in the code it originated, when known.

The plugin enriches each report with a **severity** rating and stores it,
grouping identical violations together so a problem seen on 500 pages is one row
with a counter, not 500 rows. Turning those reports into a working policy is the
subject of the [next guide](crafting-your-policy.md).

---

## A note on scope

CSP protects the **front end** — what runs in your visitors' browsers. It is one
layer of defense, not a replacement for keeping WordPress, themes, and plugins
updated, using strong credentials, and the rest of good security hygiene. Think
of it as the seatbelt: enormously valuable, especially when something else fails,
but not a reason to drive recklessly.
