# Roadmap: Expanding to a Full Security-Headers Plugin

Status: **Draft for discussion.** This document captures the competitive
analysis and the proposed plan to expand the plugin from a CSP specialist into
a comprehensive HTTP security-headers manager. It is a planning artifact, not a
commitment to scope or dates.

## 1. Context

Today the plugin is a **CSP specialist** and — as far as we can tell from the
WordPress.org directory — one of very few that does CSP *well* (Report-Only
tuning, violation reporting, source rollups). Competing "security headers"
plugins cover many headers but treat each as a static, set-and-forget string
with no reporting or tuning loop.

The goal of this roadmap is to expand coverage to **all common HTTP security
response headers** (matching the breadth of plugins like *Headers Security
Advanced & HSTS WP*) while keeping our CSP/reporting depth as the
differentiator. This is a large enough change to justify a **major version
jump**, a likely **plugin rename/rebrand**, and a **docs/guides refresh**.

## 2. Where the plugin stands today

The architecture is CSP-shaped:

- **Single header family emitted.** `send_headers` →
  `CSP_Reporting_Plugin::send_csp_headers()` iterates
  `CSP_Policy::get_headers()`, which returns only
  `Content-Security-Policy` / `-Report-Only` plus the reporting directives
  (`report-uri`, `report-to`, `Reporting-Endpoints`).
- **Deep CSP machinery around it:** structured directive→sources policy model,
  Report-Only / Enforce / Enforce+Test modes, a REST violation-report
  endpoint, a deduplicated violations table, the "By Source" rollup with
  one-click allow, notifications, WP-CLI, and multisite support.

That depth is the moat: CSP tuning is the hard, valuable part, and it is what
competitors do not have.

## 3. Target header set ("all security headers")

| Header | Effort | Notes |
|---|---|---|
| Strict-Transport-Security (HSTS) | Low build / high footgun | `max-age`, `includeSubDomains`, `preload`; needs guardrails |
| Content-Security-Policy | — | Already owned; best-in-class |
| X-Frame-Options | Trivial | Legacy; superseded by CSP `frame-ancestors` |
| X-Content-Type-Options | Trivial | `nosniff` toggle |
| Referrer-Policy | Trivial | Preset dropdown |
| Permissions-Policy (ex Feature-Policy) | Medium | Per-feature allowlist builder |
| X-XSS-Protection | Trivial | Deprecated but still requested |
| Cross-Origin-Opener-Policy (COOP) | Medium | Can emit reports via Reporting API |
| Cross-Origin-Embedder-Policy (COEP) | Medium | Can emit reports; can break embeds |
| Cross-Origin-Resource-Policy (CORP) | Low | |
| X-Permitted-Cross-Domain-Policies | Trivial | |
| Clear-Site-Data | Low | Usually scoped to logout |
| Header removal | Low | `X-Powered-By`, `Server` tokens, etc. via `header_remove()` |

## 4. Competitive positioning

- **They win on breadth, we win on depth.** Adding the static headers above is
  low engineering effort — most are a label, a value, and a toggle.
- **Our reporting infrastructure is reusable and rare.** The Reporting API
  (`Reporting-Endpoints`) we already emit for CSP can also carry **COOP/COEP,
  Deprecation, and Intervention reports**. Extending the violations pipeline to
  ingest those gives us a "reporting + tuning" story across multiple headers
  that essentially no competitor has.
- **Strategy:** reach breadth parity quickly, but build and market around the
  reporting/tuning depth so we are not "just another headers plugin."

## 5. Proposed architecture

Generalize the single `CSP_Policy::get_headers()` seam into a **header
registry**:

- Each security header becomes a small provider with: `id`, default value,
  sanitizer, settings-UI renderer, and `build_value()`.
- `send_csp_headers()` becomes a generic `send_security_headers()` that
  iterates the registry and applies each enabled provider's output.
- **CSP stays its own rich provider** (the existing policy model, unchanged);
  the simple headers are ~20-line providers.

This keeps CSP depth intact while making breadth cheap and independently
testable.

## 6. Phased plan

- **Phase 1 — Header engine + static headers.** Registry, settings storage,
  and emission for the trivial/low headers (HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, X-XSS-Protection, CORP,
  X-Permitted-Cross-Domain-Policies, header removal). Per-header toggles, sane
  presets, live preview reusing the existing preview pattern.
- **Phase 2 — Policy-shaped headers.** Permissions-Policy per-feature builder
  (reusing the directive-UI components). HSTS guardrails: preload warnings,
  "this is sticky and hard to undo," subdomain confirmation.
- **Phase 3 — Reporting expansion (the differentiator).** Wire
  COOP/COEP/Document-Policy/Deprecation/Intervention reports into the existing
  `Reporting-Endpoints` + violations pipeline. Generalize the violations table
  from "CSP violation" to "policy report" with a type column. Headline feature.
- **Phase 4 — Rename, rebrand, version jump, docs.** New display name,
  `3.0.0`, README/CHANGELOG, `docs/` guides (per-header guides alongside the
  CSP ones), wp.org readme, and a data migration for renamed option keys.

## 7. Risks and decisions to settle up front

1. **The wp.org slug is permanent.** If the plugin is ever published to the
   .org directory, the slug/folder cannot be renamed — only the display name
   changes. Decide the name **before** any .org submission. (Currently private,
   so we are still free.)
2. **Naming.** Something signaling breadth + our reporting edge (e.g.
   "Security Headers & CSP Reporting"). Factor in Matchbox branding for the
   downstream fork.
3. **Back-compat / migration.** Renaming option keys, the text domain
   (`csp-reporting`), and class prefixes (`CSP_*`) needs a one-time migration
   so existing installs keep their settings.
4. **HSTS and COEP are footguns.** HSTS is sticky; COEP breaks third-party
   embeds. Both need Report-Only-style safety and loud warnings.
5. **Scope.** Static headers are a small effort; the reporting expansion and
   rebrand are the real work. Suggested cut: ship Phases 1–2 as a point
   release, then Phase 3 as the flagship `3.0`.

## 8. Open competitive-analysis item

A line-by-line review of *Headers Security Advanced & HSTS WP* is still
pending: the source could not be fetched from the current environment
(the session's egress policy blocks `wordpress.org` / `plugins.trac.wordpress.org`).
To close this, either mirror that plugin into a repo we can read, provide its
`.zip`/readme, or run the review from an environment whose network policy
allows wordpress.org. The header set in section 3 reflects the category
standard, which should be verified against their exact current feature list.
