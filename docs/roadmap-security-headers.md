# Roadmap: Expanding to a Full Security-Headers Plugin

Status: **Draft for discussion.** This document captures the competitive
analysis and the proposed plan to expand the plugin from a CSP specialist into
a comprehensive HTTP security-headers manager. It is a planning artifact, not a
commitment to scope or dates.

## 1. Context

Today the plugin is a **CSP specialist** that does the hard part — a
first-party report→store→tune→enforce loop (Report-Only tuning, a violation
store, source rollups, one-click allow). The breadth leader in this category,
*Headers Security Advanced & HSTS WP* (100,000+ installs), covers many headers
but treats each as a static, set-and-forget string and **outsources CSP
reporting to third-party SaaS** — it stores nothing itself (see the teardown in
section 8). So the market is validated and crowded on breadth, but the
reporting/tuning depth is wide open.

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

- **They win on breadth + distribution, we win on depth.** The incumbent has
  100,000+ installs, 10+ translations, and "automatic best-practice" defaults.
  Breadth alone will not differentiate us — we would be a late entrant on the
  one axis they already dominate.
- **Their reporting is a pass-through; ours is first-party.** They append a
  `report-uri` pointing at Sentry / Report URI / URIports / Datadog and store
  nothing; first-party violation analytics sits behind their paid "Shield"
  tier. We already own the collection, dedup, rollup, and tuning loop with **no
  external subscription** — this is the durable wedge.
- **Our reporting infrastructure extends to other headers.** The Reporting API
  (`Reporting-Endpoints`) we emit for CSP can also carry **COOP/COEP,
  Deprecation, and Intervention reports**. Ingesting those first-party gives us
  a "reporting + tuning" story across multiple headers that even the breadth
  leader only offers as a pass-through.
- **Strategy:** reach breadth parity so we are a credible "all headers" choice
  (table stakes), but lead the product and messaging with first-party CSP
  reporting/tuning — "no Sentry or Report URI subscription required" — plus a
  one-click "recommended baseline" to match their zero-config UX.

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

## 8. Competitor teardown: Headers Security Advanced & HSTS WP (v5.3.3)

Based on a review of the plugin source (v5.3.3, by OpenHeaders / irn3).

**Distribution & model**
- 100,000+ active installs; 10+ bundled translations. The category's breadth
  and distribution leader.
- Freemium: every security header is free "forever"; a new **Shield** tier
  (openheaders.org/pro) adds a monitoring dashboard, a security score/scanner,
  a CSP advisor, alerts, and **CSP violation analytics** (options seen on
  uninstall: `hsts_pro_security_score`, `hsts_pro_scan_history`,
  `hsts_pro_csp_violations`).

**How it works**
- Emits headers via the `wp_headers` filter (works on any server), and
  additionally writes HSTS/CSP into **`.htaccess`** on Apache
  (`insert_with_markers`-style block, rewritten on option change and on
  plugin upgrade).
- "Automatic best practices": hardcoded sensible defaults with mostly on/off
  `disable_*` toggles. Example built-in Permissions-Policy is a full
  feature-by-feature default string; default CSP is minimal
  (`upgrade-insecure-requests;`).

**Header coverage** (superset of our section 3): CORS
(`Access-Control-Allow-Origin/Methods/Headers`), CSP + legacy
`X-Content-Security-Policy`, COEP/COOP/CORP incl. `-Report-Only`,
Permissions-Policy, Referrer-Policy, HSTS, X-Content-Type-Options,
X-Frame-Options, X-Permitted-Cross-Domain-Policies, `X-Powered-By` removal,
Clear-Site-Data, FLoC opt-out, and deprecated Expect-CT / HPKP / Pragma /
X-XSS-Protection.

**The decisive gap — CSP reporting is pass-through only.** The `report-uri`
setting (`hsts_csp_report_uri`) simply appends `report-uri`/`report-to`
pointing at an **external service** (Sentry, Report URI, URIports, Datadog).
There is **no first-party REST endpoint, no violations table, no dedup, no "By
Source" rollup, no one-click allow, and no structured directive builder**.
Free-tier users must buy a third-party SaaS subscription (or Shield) to
actually see and tune violations. This is exactly the workflow we already own.

**Weaknesses worth exploiting**
- CSP is a near-static default string; there is no data-driven tuning loop.
- Some questionable always-on defaults (e.g. CORS `Access-Control-Allow-*`
  emitted on every response; COEP/COOP `report-to='default'` referencing a
  reporting group that is not necessarily defined).
- `.htaccess` rewriting is fragile across hosts/servers.
- No first-party analytics without paying or wiring up external SaaS.

**What they do better than us today**
- Breadth of headers, zero-config "recommended" defaults, `.htaccess` option
  for server-level enforcement, and heavy internationalization.

**Net:** adopt their breadth and zero-config baseline as table stakes; keep our
first-party reporting/tuning as the headline differentiator and extend it to
COOP/COEP reports, which even they only pass through.
