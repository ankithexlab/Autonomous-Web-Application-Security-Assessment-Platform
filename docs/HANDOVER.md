# Phase 1 Handover Documentation — Foundation Repair

## Overview
This document records the completion of **Phase 1: Foundation Repair** for the Autonomous Web Application Security Assessment Platform (AWASAP).

---

## 1. Environment & Setup

### Prerequisites
- **Python**: 3.11+ (verified on Python 3.13.12)
- **Node.js**: 18+ (verified on Node v25.8.1 with npm 11.11.0 / pnpm 11.17.0)
- **Database**: PostgreSQL 16+ (or local SQLite for lightweight local dev)

### Quick Start
To launch the entire stack in development mode:
```bat
:: From repository root
run.bat
```
This automatically boots:
1. Backend on `http://127.0.0.1:8000` (docs at `/docs`)
2. Frontend Vite dev server on `http://localhost:5173`

---

## 2. Key Commands Reference

### Backend
From `backend/`:
```bash
# Activate virtual environment
.venv\Scripts\activate

# Install / update dependencies
pip install -r requirements.txt

# Run migrations
alembic current
alembic upgrade head

# Run full test suite (267 tests)
pytest tests -q

# Run backend server directly
uvicorn app.main:app --reload --port 8000
```

### Frontend
From repository root:
```bash
# Install dependencies
npm install  # or pnpm install

# Run development server
npm run dev

# Run TypeScript check and production build
npm run build

# Run linter
npm run lint
```

---

## 3. Security & Configuration Boundaries

- **Secrets Policy**: 
  - Never commit `.env` files. Both root `.env` and `backend/.env` are ignored by Git.
  - Template reference files (`.env.example`, `backend/.env.example`) contain placeholders only.
- **Production Pre-flight Guardrails**:
  - The backend will refuse to boot with `DEBUG=false` if:
    - `SECRET_KEY` is empty, shorter than 32 characters, contains known placeholder tokens, or has low entropy.
    - `DATABASE_URL` is set to SQLite.
    - `CORS_ORIGINS` contains wildcard `'*'` or plain HTTP non-localhost origins.
    - `FRONTEND_URL` is plain HTTP for public domains.

---

## 4. Verification Checkpoint Status

- [x] Backend configuration and environment variables verified
- [x] Python 3.13 and Node.js v25 compatibility confirmed
- [x] Database connectivity to PostgreSQL 16.15 verified
- [x] Alembic migrations upgraded to head (`0011`)
- [x] CORS and security headers active on FastAPI
- [x] Full backend regression tests passed (`267 passed`)
- [x] Backend startup, liveness (`/health`), and readiness (`/readiness`) verified
- [x] Frontend TypeScript typecheck and production build verified (`tsc -b && vite build`)
- [x] Project status and handover documentation published

---

**Next Phase**: Ready for subsequent feature phases or deployment pipelines.

---

# Phase 2 Handover Documentation — Backend & Database Repair

## Overview

Phase 2 audited and repaired the entire backend: ORM models, repositories, services, and API routers. All fixes are tested and verified. No schema migrations were added (alembic check clean).

---

## 1. Files Changed

| File | Change Summary |
|---|---|
| `backend/app/models/user.py` | Removed duplicate `id`, added `id` override with migration comment, fixed `role` column type to `String(20)`, added `scans`/`findings`/`reports` relationships |
| `backend/app/models/project.py` | Added `findings`, `reports` relationships with cascade |
| `backend/app/models/target.py` | Added `findings` relationship with cascade |
| `backend/app/models/scan.py` | Fixed `user` relationship `back_populates` |
| `backend/app/models/finding.py` | Fixed `target`, `project`, `user` relationship `back_populates` |
| `backend/app/models/report.py` | Fixed `project`, `user` relationship `back_populates` |
| `backend/app/repositories/user.py` | Added `delete()` |
| `backend/app/repositories/target.py` | Added `update()`, `delete()` |
| `backend/app/repositories/scan.py` | Added `delete()` |
| `backend/app/repositories/finding.py` | Added `delete()` |
| `backend/app/repositories/report.py` | Added `delete()` |
| `backend/app/services/target.py` | Added `get_user_target()`, `delete_target()`, `delete_user_target()` |
| `backend/app/services/scan.py` | Added `delete_scan()` with RUNNING guard |
| `backend/app/services/auth.py` | Added `delete_account()` with token revocation |
| `backend/app/api/v1/auth.py` | Added `DELETE /auth/me` |
| `backend/app/api/v1/targets.py` | Added `GET /targets/{id}`, `DELETE /targets/{id}`, `DELETE /projects/{id}/targets/{id}` |
| `backend/app/api/v1/scans.py` | Added `DELETE /scans/{id}` |
| `backend/app/api/v1/findings.py` | Added `DELETE /findings/{id}` |
| `backend/app/api/v1/reports.py` | Added `DELETE /reports/{id}` |
| `backend/app/api/v1/dashboard.py` | Added `GET /dashboard/notifications` |
| `backend/app/schemas/dashboard.py` | Added `NotificationItem` schema |
| `backend/tests/test_phase2_repairs.py` | **New** — 23 Phase 2-specific tests (auth, IDOR, delete lifecycle, notifications, model relationships) |

---

## 2. New API Endpoints

```
DELETE /api/v1/auth/me                            → 200 (account deletion + token revocation)
GET    /api/v1/targets/{target_id}                → 200 (flat-route single target lookup)
DELETE /api/v1/targets/{target_id}                → 204 (IDOR protected)
DELETE /api/v1/projects/{pid}/targets/{tid}       → 204 (project-scoped, IDOR protected)
DELETE /api/v1/scans/{scan_id}                    → 204 (RUNNING guard + ownership check)
DELETE /api/v1/findings/{finding_id}              → 204 (IDOR protected)
DELETE /api/v1/reports/{report_id}                → 204 (IDOR protected)
GET    /api/v1/dashboard/notifications            → 200 list[NotificationItem]
```

---

## 3. Security Properties (Verified)

| Property | Verification |
|---|---|
| Unauthenticated → 401 | All 7 DELETE/GET endpoints tested (23 test suite) |
| Cross-user IDOR → 404 | 3 IDOR tests pass (target, scan, project-scoped target) |
| Token revoked after deletion | `test_token_revoked_after_account_deletion` passes |
| RUNNING scan cannot be deleted | Guard in `services/scan.py::delete_scan()` |
| Alembic drift-free | `alembic check` → `No new upgrade operations detected` |

---

## 4. Test Results

```
Phase 2 specific tests:  23/23  ✅
Full regression suite:  290/290 ✅  (267 baseline + 23 Phase 2)
Warnings:               6 (pre-existing RuntimeWarning: coroutine never awaited — not failures)
```

---

## 5. Architecture Notes

- **Notifications** are derived from `DashboardService.get_user_summary()` → `recent_activities`. No persistent `Notification` model or table was created. If a persistent notification store is required, that is Phase 3+ scope.
- **Scanner modules** (`services/scanner/`, `services/scanner_engine.py`) were not audited in Phase 2. They are tested through existing scanner integration tests (267 baseline tests include scanner tests).
- **No new Alembic migration** was needed — all ORM changes were comment/relationship-level and did not alter any column DDL.

---

## 6. Verification Checkpoint Status

### Phase 1
- [x] Backend configuration and environment variables verified
- [x] Python 3.13 and Node.js v25 compatibility confirmed
- [x] Database connectivity to PostgreSQL 16.15 verified
- [x] Alembic migrations upgraded to head (`0011`)
- [x] CORS and security headers active on FastAPI
- [x] Full backend regression tests passed (`267 passed`)
- [x] Backend startup, liveness (`/health`), and readiness (`/readiness`) verified
- [x] Frontend TypeScript typecheck and production build verified (`tsc -b && vite build`)

### Phase 2
- [x] ORM schema drift resolved — `alembic check` clean
- [x] All model relationships correctly wired with `back_populates` and `cascade`
- [x] Repository layer complete — all models have full CRUD
- [x] Service layer complete — IDOR protection on all delete operations
- [x] API layer complete — all missing DELETE endpoints added
- [x] Dashboard notifications endpoint added and tested
- [x] Account deletion with token revocation verified
- [x] 23 Phase 2 regression tests written and passing
- [x] Full suite: 290/290 passed — zero regressions

### Phase 3
- [x] Real frontend/backend API integration across all 10 feature pages
- [x] All 8 Phase 2 endpoints wired into UI components (delete account, get/delete targets, delete scan, delete finding, delete report, dashboard notifications)
- [x] Removed remaining mock/fake UI states and hardcoded fallbacks
- [x] Clean zero-state and empty states implemented across all metrics and charts
- [x] Error handling with inline user alerts and retry actions configured
- [x] Route definitions, navigation links, and command search (`ROUTES.PAYLOADS`) verified
- [x] Production build passes cleanly: `tsc -b && vite build` (0 TypeScript errors)
- [x] Frontend linting verified: `oxlint .` (0 warnings, 0 errors on 186 files)
- [x] Full backend regression suite verified: 290 / 290 passed (100%)
- [x] Database migrations verified: `alembic check` clean (0 pending migrations)

---

# Phase 3 Handover Documentation — Full Frontend & API Integration

## Overview

Phase 3 established full end-to-end integration between the React + Vite frontend and the FastAPI backend. All 10 application views (Dashboard, Projects, Targets, Scans, Findings, OWASP Top 10, Reports, Payloads, AI Assistant, and Settings) consume real backend API services with zero mock data fallbacks.

---

## 1. Verified Integration Matrix

| Feature | Primary API Route | Integration Component | Verified Capabilities |
|---|---|---|---|
| **Auth & Session** | `/api/v1/auth/*` | `useAuthStore`, `authService` | Login, Register, Rehydrate, Logout, Password Change, Account Deletion (`DELETE /auth/me`) |
| **Dashboard** | `/api/v1/dashboard/summary` | `DashboardPage`, `NotificationPanel` | Live metrics, radial posture score, risk gauge, scan activity, threat velocity, recent findings |
| **Projects** | `/api/v1/projects/*` | `ProjectsPage`, `ProjectModal`, `DeleteProjectDialog` | Real-time project listing, creation, editing, status toggle, and deletion |
| **Targets** | `/api/v1/targets/*`, `/api/v1/projects/{pid}/targets/*` | `TargetsPage`, `AddTargetDialog`, `TargetDetailPanel` | Target registration, project association, single target retrieval (`GET /targets/{id}`), flat/scoped deletion |
| **Scans** | `/api/v1/scans/*` | `ScansPage`, `useScanEngine`, `ScanDetailView`, `ScanQueuePanel` | Scan configuration, start/cancel/delete scan (`DELETE /scans/{id}`), active execution queue |
| **Findings** | `/api/v1/findings/*` | `FindingsPage`, `FindingTable`, `FindingDetailView` | Server-side filtering, status updates, deletion (`DELETE /findings/{id}`), CSV export |
| **OWASP Top 10** | `/api/v1/owasp/summary` | `OWASPDashboardPage` | Live findings mapping across 10 OWASP categories, 6-month risk trend, affected asset ranking |
| **Reports** | `/api/v1/reports/*` | `ReportsPage`, `GenerateReportDialog`, `ReportHistoryTable`, `ReportPreviewSheet` | Scoped generation, deletion (`DELETE /reports/{id}`), visual document preview, multi-format download |
| **Payloads** | `/api/v1/payloads/*` | `PayloadsPage` | Paginated library, search, severity filters, payload inspect modal, copy to clipboard |
| **AI Assistant** | `/api/v1/ai/chat`, `/api/v1/ai/status` | `AIAssistantPage` | Interactive security assistant chat, markdown formatting, code block extraction, diagnostic error alerts |
| **Settings** | `/api/v1/auth/me` | `SettingsPage`, `AccountSettingsTab` | Profile editing, password change, organization settings, JSON export, cache purge, account purge |

---

## 2. Verification Checkpoint Status

- [x] Frontend production build verified (`tsc -b && vite build` built in 1.44s)
- [x] Frontend linting verified (`oxlint .` passed with 0 errors and 0 warnings)
- [x] Full backend regression tests passed (290 / 290 passed)
- [x] Alembic migration schema state verified (`alembic check` clean)
- [x] All 8 Phase 2 endpoints wired and tested
- [x] Mock data removed from UI pages and components
- [x] Project documentation (`PROJECT_STATUS.md` and `HANDOVER.md`) updated

---

**Phase 3 Status**: COMPLETE. Standing by for user instruction before Phase 4.

---

# Phase 4 Handover Documentation — Real Scanner Engine & Assessment Verification

## Overview

Phase 4 audited and hardened the scanner execution engine and all surrounding UI surfaces. It eliminated fake findings, simulated progress, silent fallbacks, and untruthful module statuses. All deliverables are tested and verified. No schema migrations were added (`alembic check` clean).

---

## 1. Files Changed

| File | Change Summary |
|---|---|
| `backend/app/services/scanner_engine.py` | Updated `MODULE_ALIAS_MAP` so `"crawler"` resolves to `["crawler", "url_discovery"]`; added incremental `modules_json` persistence after each stage and in `CancelledError`/fatal exception handlers |
| `src/services/scans.service.ts` | Added `parseModulesJson()` to deserialize `modules_json`; removed `https://app.acmecorp.com` silent fallback; added imports for `ScanModule` and `ScanModuleStatus` |
| `src/types/scan.ts` | Added `modulesJson?: string \| null` field to `Scan` interface |
| `src/features/scans/hooks/use-scan-engine.ts` | `activeModules` prefers backend-parsed modules over synthetic intervals; `totalRequests` derived from real data |
| `src/features/scans/components/scan-detail-view.tsx` | Implemented `extractReconResults()` and wired `<InfoGatheringResults>` Reconnaissance tab with real persisted data |
| `src/features/targets/pages/targets-page.tsx` | Removed `https://new-target.acmecorp.com` silent fallback; replaced with explicit `toast.error()` |
| `backend/tests/test_phase4_verification.py` | **New** — 5 Phase 4-specific verification tests |

---

## 2. Security Properties Verified

| Property | Test / Evidence |
|---|---|
| SSRF — RFC 1918 blocked | `test_ssrf_rejects_private_and_cloud_metadata`: 10.x, 172.16.x, 192.168.x all raise `BadRequestException` ✅ |
| SSRF — Loopback blocked | `127.0.0.1`, `localhost` raise `BadRequestException` ✅ |
| SSRF — Link-local / cloud metadata blocked | `169.254.169.254`, `metadata.google.internal` raise `BadRequestException` ✅ |
| DNS rebinding interception | `SafeNetworkBackend.connect_tcp()` re-checks resolved IP via `is_ip_blocked()` before each TCP connection ✅ |
| Redirect re-validation | Each hop calls `validate_target_url()`; max 5 hops enforced ✅ |
| TLS enforcement | `SafeHTTPClient(verify=True)` default; self-signed certs rejected in production mode ✅ |
| Response bomb protection | `SafeHTTPClient(max_response_bytes=1_048_576)` — streaming read capped at 1 MB ✅ |
| Cancellation preserves state | `test_mid_scan_cancellation_preserves_modules_json`: `CANCELLED` status + non-null `modules_json` after `CancelledError` ✅ |
| No silent fallbacks | `app.acmecorp.com` / `new-target.acmecorp.com` removed — explicit errors surfaced to user ✅ |
| Crawler alias correct | `test_crawler_alias_resolution`: `MODULE_ALIAS_MAP["crawler"]` includes `"url_discovery"` ✅ |

---

## 3. Operational Limits

| Limit | Value |
|---|---|
| Max response body | 1 MB per HTTP response |
| Global scan timeout | 10 minutes |
| HTTP connect timeout | 10 seconds |
| HTTP read timeout | 30 seconds |
| Max redirect hops | 5 (each re-validated) |
| Permitted targets | Public routable IPs/FQDNs only |
| TLS validation | Enforced — `verify=True` |
| Cancellation persistence | Partial `modules_json` written on `CancelledError` |

---

## 4. Test Results

```
Phase 4 specific tests:   5/5    ✅  (test_phase4_verification.py)
Phase 4 + scanner tests:  129/129 ✅  (-k "phase or scanner or crawler or sqli or detection")
Full regression suite:    295/295 ✅  (231.55s — 0 failures, 6 pre-existing warnings)
Frontend production build: 0 TypeScript errors, built in 1.78s ✅
```

Pre-existing warnings (not failures):
- `RuntimeWarning: coroutine 'ScanService.start_scan.<locals>._async_background_runner' was never awaited` — from test mock isolation in Phase 5.1/5.2 test helpers.
- `RuntimeWarning: coroutine 'Connection._cancel' was never awaited` — from async SQLite cancel mock in connection tests.

---

## 5. Architecture Notes

- **Incremental persistence**: `scanner_engine.py` now writes `modules_json` after every stage rather than only at completion. This means partial execution data is always recoverable from the database on crash, cancel, or timeout.
- **No new Alembic migration**: The `modules_json` column already existed. No DDL changes were required.
- **Frontend type safety**: `ScanModule` and `ScanModuleStatus` are imported from `@/types` — the build now fails fast if the type contract breaks.
- **Scanner module naming**: `SameOriginCrawlerModule` is registered with `module_id = "url_discovery"` by design; the alias map is the correct authoritative mapping layer.

---

## 6. Verification Checkpoint Status

### Phase 1
- [x] Backend configuration and environment variables verified
- [x] Python 3.13 and Node.js v25 compatibility confirmed
- [x] Database connectivity to PostgreSQL 16.15 verified
- [x] Alembic migrations upgraded to head (`0011`)
- [x] CORS and security headers active on FastAPI
- [x] Full backend regression tests passed (`267 passed`)
- [x] Backend startup, liveness (`/health`), and readiness (`/readiness`) verified
- [x] Frontend TypeScript typecheck and production build verified (`tsc -b && vite build`)

### Phase 2
- [x] ORM schema drift resolved — `alembic check` clean
- [x] All model relationships correctly wired with `back_populates` and `cascade`
- [x] Repository layer complete — all models have full CRUD
- [x] Service layer complete — IDOR protection on all delete operations
- [x] API layer complete — all missing DELETE endpoints added
- [x] Dashboard notifications endpoint added and tested
- [x] Account deletion with token revocation verified
- [x] 23 Phase 2 regression tests written and passing
- [x] Full suite: 290/290 passed — zero regressions

### Phase 3
- [x] Real frontend/backend API integration across all 10 feature pages
- [x] All 8 Phase 2 endpoints wired into UI components
- [x] Removed remaining mock/fake UI states and hardcoded fallbacks
- [x] Clean zero-state and empty states implemented across all metrics and charts
- [x] Error handling with inline user alerts and retry actions configured
- [x] Route definitions, navigation links, and command search (`ROUTES.PAYLOADS`) verified
- [x] Production build passes cleanly: `tsc -b && vite build` (0 TypeScript errors)
- [x] Frontend linting verified: `oxlint .` (0 warnings, 0 errors on 186 files)
- [x] Full backend regression suite verified: 290 / 290 passed (100%)
- [x] Database migrations verified: `alembic check` clean (0 pending migrations)

### Phase 4
- [x] Crawler module alias map corrected (`"crawler"` → `["crawler", "url_discovery"]`)
- [x] Incremental `modules_json` persistence after each scan stage
- [x] `modules_json` written on `CancelledError` and fatal exception
- [x] SSRF protections verified: RFC1918, loopback, link-local, cloud metadata all blocked
- [x] DNS rebinding interception verified at connection layer (`SafeNetworkBackend`)
- [x] Redirect re-validation verified (max 5 hops, each re-validated)
- [x] TLS enforcement verified (`verify=True`, production mode rejects plain HTTP)
- [x] Response byte cap verified (1 MB ceiling via `SafeHTTPClient.max_response_bytes`)
- [x] Silent `acmecorp.com` fallbacks removed from frontend services and pages
- [x] Frontend `parseModulesJson()` added for truthful module status display
- [x] Frontend Reconnaissance tab wired to real `modules_json` data
- [x] 5 Phase 4 verification tests written and passing
- [x] Full regression suite: 295 / 295 passed — zero regressions
- [x] Frontend production build verified: 0 TypeScript errors, 1.78s build time
- [x] Project documentation (`PROJECT_STATUS.md` and `HANDOVER.md`) updated

---

**Phase 4 Status**: COMPLETE.

---

# Phase 5 Handover Documentation — Passive Scanner Modules

## Overview

Phase 5 implemented, tested, and integrated all 10 genuine passive security analysis modules into the AWASAP assessment platform. Every module operates strictly on collected HTTP response data and target metadata. Findings are supported by real evidence with credentials and secret parameter values redacted. No intrusive attack payloads, state mutations, or data modification are performed.

---

## 1. Files Created & Modified

| File | Change Summary |
|---|---|
| `backend/app/services/scanner/security_headers.py` | **New** — `SecurityHeadersModule` (`security_headers`): Analyzes 10 security response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP) and flags missing headers or unsafe directives (`unsafe-inline`, `unsafe-eval`). |
| `backend/app/services/scanner/ssl_tls.py` | **New** — `SslTlsModule` (`ssl_tls`): Direct TLS inspection over socket (version, cipher, certificate validity, expiration, issuer, SANs). Flags expired, soon-expiring, untrusted/self-signed certs, deprecated TLS (SSLv2/3, TLS 1.0/1.1), and weak ciphers. |
| `backend/app/services/scanner/cookie_security.py` | **New** — `CookieSecurityModule` (`cookie_security`, alias `cookie_audit`): Per-cookie analysis of `Set-Cookie` headers for missing `Secure`, `HttpOnly`, `SameSite` flags and dangerous `SameSite=None` without `Secure`. Redacts cookie values in PoC evidence (`<redacted>`). |
| `backend/app/services/scanner/http_config.py` | **New** — `HttpConfigModule` (`http_config`): Cleartext HTTP detection, HTTP-to-HTTPS redirect verification, and passive mixed-content detection (`http://` resources on HTTPS pages). |
| `backend/app/services/scanner/redirect_analysis.py` | **New** — `RedirectAnalysisModule` (`redirect_analysis`, alias `https_redirect`): Multi-hop redirect chain analysis, detecting protocol downgrade (HTTPS -> HTTP), excessive hops (>3), and cross-origin query parameter leaks. |
| `backend/app/services/scanner/tech_detection.py` | **Preserved & Integrated** — `TechDetectionModule` (`tech_detection`): Passive fingerprinting of web servers, frameworks, CMS, languages, and JS libraries; flags outdated jQuery. |
| `backend/app/services/scanner/robots_sitemap.py` | **New** — `RobotsSitemapModule` (`robots_sitemap`): Discovery and analysis of `/robots.txt` and `/sitemap.xml`. Flags information disclosure where administrative, internal, or backup endpoints are published in `Disallow:` directives or sitemap `<loc>` entries. |
| `backend/app/services/scanner/crawler.py` | **Preserved & Integrated** — `SameOriginCrawlerModule` (`url_discovery`, alias `crawler`): Breadth-first crawl bounded by depth (max 2), URLs (max 25), per-request timeout (4.0s), and 15s duration budget with state-changing action keyword exclusion. |
| `backend/app/services/scanner/endpoint_param_discovery.py` | **New** — `EndpointParamDiscoveryModule` (`endpoint_discovery`): Analyzes crawler-discovered URLs and query strings without network requests. Extracts unique paths and parameter names, flags sensitive parameter names, numeric ID paths, and legacy extensions; redacts query values (`param=<redacted>`). |
| `backend/app/services/scanner/exposed_config_checker.py` | **New** — `ExposedConfigCheckerModule` (`exposed_config`): Probes 25+ sensitive configuration and backup files (`/.env`, `/.git/HEAD`, `/config.php`, `/web.config`, `/backup.sql`, etc.) with content marker validation to eliminate soft-404 false positives and redacts secrets from PoC evidence. |
| `backend/app/services/scanner_engine.py` | **Updated** — Registered all 10 modules in `MODULE_ALIAS_MAP` under `"passive"`, `"headers"`, `"ssl"`, `"crawler"`, and `"recon"` presets. Integrated Stage 4 (headers, cookies), Stage 5 (SSL/TLS, HTTP config, redirects), and Stage 6 (robots/sitemap, endpoint discovery, exposed config, tech disclosure). Serializes `modules_json` incrementally. |
| `backend/tests/test_phase5_passive_modules.py` | **New** — Comprehensive 13-test suite verifying all 10 modules, error handling, cancellation, sensitive data redaction, and full engine integration. |

---

## 2. Tested Security Properties & Redaction

| Property | Test / Evidence |
|---|---|
| **Cookie Value Redaction** | `test_cookie_security_missing_flags_and_redaction`: raw session tokens replaced with `<redacted>` in finding PoC ✅ |
| **URL Query Value Redaction** | `test_endpoint_and_param_discovery_redacts_values`: query parameter values replaced with `param=<redacted>` in finding PoC ✅ |
| **Configuration File Secret Redaction** | `test_exposed_config_checker_identifies_env_and_git`: database passwords and application keys in `/.env` omitted from PoC ✅ |
| **SSRF Guardrails Intact** | Pre-flight SSRF check (`validate_target_url`) and connection-time IP interception (`SafeNetworkBackend`) active across all module requests ✅ |
| **Response Byte Cap Intact** | 1 MB streaming ceiling enforced across all requests via `SafeHTTPClient.max_response_bytes` ✅ |
| **Non-Destructive & Passive** | Zero attack payloads, zero data modification, bounded GET requests only ✅ |

---

## 3. Verified Test Results

```
Phase 5 specific tests:    13 / 13 passed  ✅  (backend/tests/test_phase5_passive_modules.py)
Scanner regression tests:  31 / 31 passed  ✅  (Phase 4, Phase 5, engine, crawler, e2e)
Full backend test suite:  308 / 308 passed  ✅  (100% pass rate in 261.21s, 0 failures)
Frontend production build: 0 TypeScript errors, built in 3.02s ✅
```

---

# Phase 6 Handover Documentation — Active Vulnerability Detection

## Overview

Phase 6 designed, implemented, and verified genuine, safe, non-destructive active vulnerability detection across all 7 mandated security domains. All active modules require explicit target authorization and separate active scan confirmation (`active_confirmed=True`), send harmless probes only, rate-control requests with per-probe delays, cap timeouts at 5.0s, redact sensitive tokens/passwords/JWTs (`[REDACTED]`), and preserve all Phase 4 & Phase 5 SSRF protections and response limits.

---

## 1. Files Created & Modified

| File | Change Summary |
|---|---|
| `backend/app/schemas/scan.py` | Added `active_confirmed: bool = Field(default=False)` to `ScanCreateRequest`. |
| `backend/app/services/scan.py` | Enforced dual active scan authorization gate: verifies target authorization status (`validation_status != 'rejected'`), requires `active_confirmed=True` for active scans, and records `active_scan_confirmed: True` in `config_json`. |
| `backend/app/services/scanner/base_module.py` | Added `confidence` argument to `_create_finding()`, implemented `BaseScannerModule.is_active_confirmed(scan)` helper, and added regex-based sensitive secret redaction (`_redact_sensitive_content`) for Bearer tokens, passwords, API keys, and JWTs. |
| `backend/app/services/scanner/sqli_detector.py` | Enhanced with safe active probing: single-quote syntax error detection across multi-database error signatures (`CONFIRMED`), and arithmetic boolean differentials (`1*1` vs `1*0`, `'1'='1` vs `'1'='2'`) (`POTENTIAL`). Zero data extraction or destructive execution. |
| `backend/app/services/scanner/xss_detector.py` | Enhanced with safe active probing: injects harmless unique canary strings (`awasap_xss_<id>`) and safe delimiter probes (`">xss_probe<`). Verifies unencoded contextual HTML reflection (`CONFIRMED`) without executing arbitrary script payloads. |
| `backend/app/services/scanner/csrf_detector.py` | Enhanced with active validation: identifies state-changing HTML forms (`POST`/`PUT`/`DELETE`), checks anti-CSRF token presence, evaluates cookie `SameSite` flags, and safely probes POST endpoints with cross-origin headers without valid tokens (`CONFIRMED`). |
| `backend/app/services/scanner/session_analyzer.py` | Enhanced with active checks: Shannon entropy and length predictability checks on session cookies, cleartext HTTP login credential transmission detection (`CONFIRMED`), and active post-logout session invalidation verification (`CONFIRMED`). |
| `backend/app/services/scanner/idor_detector.py` | Enhanced with active checks: discovers predictable and sequential numeric/UUID identifiers (`/api/users/101`), tests controlled lab test object IDs for missing authorization checks (`CONFIRMED`), and probes out-of-bounds sequential identifiers (`999999`) (`POTENTIAL`). |
| `backend/app/services/scanner/api_security.py` | Enhanced with active checks: probes HTTP `TRACE` method for Cross-Site Tracing (XST) reflection of credentials (`CONFIRMED`), inspects `OPTIONS` response `Allow` headers for dangerous methods (`PUT`, `DELETE`, `DEBUG`), and evaluates rate limiting thresholds with bounded rapid request bursts. |
| `backend/app/services/scanner/input_validation.py` | **New** — `InputValidationModule`: Actively tests parameters with safe boundary probes: integer/string type confusion, length boundaries (1,024 repetitions), and URL-encoded null bytes (`%00`). Flags unhandled HTTP 500 server crashes and unhandled stack traces (`CONFIRMED`). |
| `backend/app/services/scanner_engine.py` | Registered `active` preset in `MODULE_ALIAS_MAP`, records `active_scan_authorization` in `modules_json`, and registered `InputValidationModule` in the module pipeline. |
| `backend/tests/test_phase6_active_modules.py` | **New** — 16 comprehensive lab tests covering authorization enforcement, scan confirmation, SQLi, XSS, CSRF, Session, IDOR, API security, input validation, full scanner engine integration, and evidence redaction. |
| `src/types/scan.ts` | Added `'active'` and `'passive'` to `ScanType` union. |
| `src/services/scans.service.ts` | Added `activeConfirmed?: boolean` to `CreateScanPayload`. |
| `src/features/scans/components/scan-detail-view.tsx` | Added `'active'` and `'passive'` icon configs in `typeConfig`. |
| `src/features/scans/components/scan-status-cards.tsx` | Added `'active'` and `'passive'` icon configs in `typeConfig`. |

---

## 2. Tested Security Properties & Redaction

| Property | Test / Evidence |
|---|---|
| **Target Authorization & Confirmation Gate** | `test_active_scan_requires_confirmation_on_create`, `test_start_scan_enforces_target_authorization_and_active_gate`: active scan rejected without explicit confirmation or if target rejected ✅ |
| **SQLi Harmless Detection Probes** | `test_sqli_active_quote_probe_confirmed_finding`, `test_sqli_active_boolean_differential_potential_finding`, `test_sqli_active_secure_endpoint_no_finding` ✅ |
| **XSS Canary Reflection Probing** | `test_xss_active_canary_reflection_confirmed_finding`, `test_xss_active_encoded_reflection_not_vulnerable`: unencoded angle brackets/quotes flagged as CONFIRMED; HTML-encoded inputs not vulnerable ✅ |
| **CSRF Active Validation Probing** | `test_csrf_active_validation_confirmed_finding`, `test_csrf_active_rejected_by_token_check`: unprotected cross-origin POST flagged as CONFIRMED; token-protected rejected safely ✅ |
| **Session Entropy & Invalidation** | `test_session_analyzer_logout_invalidation_active_check`, `test_cleartext_login_form_transmission_detected`: post-logout active cookie validity flagged as CONFIRMED ✅ |
| **IDOR Controlled Test ID Access** | `test_idor_controlled_test_id_confirmed_finding`: accessible controlled cross-user test ID flagged as CONFIRMED ✅ |
| **API TRACE & Method Inspection** | `test_api_security_trace_xst_and_methods_active_check`: HTTP TRACE reflection flagged as CONFIRMED ✅ |
| **Input Boundary Crash Detection** | `test_input_validation_active_type_confusion_crash_detected`: unhandled HTTP 500 error flagged as CONFIRMED ✅ |
| **Secret & Token Redaction** | `test_evidence_redaction_prevents_secret_leakage`: Bearer tokens, passwords, and API keys replaced with `[REDACTED]` in PoC evidence ✅ |
| **Engine Integration** | `test_scanner_engine_full_integration_with_active_confirmation`: full scan pipeline persists `active_scan_authorization` and all module outcomes in `modules_json` ✅ |

---

## 3. Verified Test Results

```
Phase 6 specific tests:    16 / 16 passed  ✅  (backend/tests/test_phase6_active_modules.py) in 6.22s
Scanner regression tests:  47 / 47 passed  ✅  (Phases 4, 5, 6, engine, crawler, e2e)
Full backend test suite:  324 / 324 passed  ✅  (100% pass rate in 262.25s, 0 failures)
Frontend production build: 0 TypeScript errors, built in 2.41s ✅
```

---

# Phase 7 Handover Documentation — OWASP Engine & Findings

## Overview

Phase 7 audited, enhanced, and completed the OWASP Top 10 (2021 standard) mapping and end-to-end findings lifecycle. Every category (A01 through A10) implements genuine detection logic with fault-isolated execution in `OWASPEngine`. Finding deduplication was upgraded to be scan-aware, ensuring site-wide configurations deduplicate globally while distinct endpoint vulnerabilities on different URLs are preserved. The findings lifecycle now fully supports `open`, `confirmed`, `in_progress`, `resolved`, `reopened`, `false_positive`, and `accepted_risk`, with real-time dynamic OWASP posture score and category compliance recalculation.

---

## 1. Files Created & Modified

| File | Change Summary |
|---|---|
| `backend/app/services/owasp/checkers/a09_logging_failures.py` | Implemented genuine passive checks for missing request traceability headers (`X-Request-ID`) on API endpoints (CWE-778) and unhandled diagnostic exception stack traces in error responses (CWE-209). |
| `backend/app/services/owasp/checkers/a05_misconfiguration.py` | Fixed CWE mapping on missing X-Content-Type-Options from CWE-79 to canonical CWE-693. |
| `backend/app/services/owasp/owasp_engine.py` | Enhanced orchestrator with per-checker fault isolation (`try...except`) and structured execution telemetry. |
| `backend/app/repositories/finding.py` | Upgraded `FindingRepository.create()` deduplication: scan-wide deduplication for site-wide configuration headers; preservation of distinct endpoint findings on different URLs for injection and vulnerability checks. |
| `backend/app/api/v1/findings.py` | Added `"reopened"` to `VALID_STATUSES` to support full findings lifecycle state transitions. |
| `backend/app/schemas/finding.py` | Documented `"reopened"` in `FindingStatusUpdateRequest`. |
| `backend/app/api/v1/owasp.py` | Upgraded `GET /api/v1/owasp/summary` to calculate overall risk score and category compliance dynamically based on active unresolved findings (`open`, `confirmed`, `reopened`, `in_progress`), removing penalties when findings are resolved or marked false positive. Robust matching for all OWASP category formats. |
| `src/types/finding.ts` | Added `"reopened"` to frontend `FindingStatus` union. |
| `src/services/findings.service.ts` | Added `"reopened"` to status validation in `normaliseFinding`. |
| `src/features/findings/components/finding-filters.tsx` | Added `"reopened"` to filter options. |
| `src/features/findings/components/finding-table.tsx` | Added `"reopened"` to status badges, and enhanced dropdown menu with complete lifecycle actions: "Mark Resolved", "Mark False Positive", "Accept Risk", and "Reopen Finding". |
| `backend/tests/test_phase7_owasp_findings.py` | Comprehensive 19-test suite verifying all 10 OWASP categories, fault isolation, multi-URL deduplication, cross-user and cross-target isolation, lifecycle transitions, IDOR protection, tracking header classification, cookie redaction, and dynamic dashboard recalculation. |

---

## 2. Tested Security Properties & Lifecycle

| Property | Test / Evidence |
|---|---|
| **A01 Broken Access Control** | `test_owasp_a01_broken_access_control`: `.env` / credentials exposure flagged as A01:2021 (CWE-538, CVSS 9.1) ✅ |
| **A02 Cryptographic Failures** | `test_owasp_a02_cryptographic_failures`: cleartext HTTP (CWE-319) and missing HSTS (CWE-523) flagged as A02:2021 ✅ |
| **A03 Injection** | `test_owasp_a03_injection`: unhandled SQL syntax error flagged as A03:2021 (CWE-89, CVSS 7.5) ✅ |
| **A04 Insecure Design** | `test_owasp_a04_insecure_design`: missing rate-limiting headers flagged as A04:2021 (CWE-799, CVSS 3.1) ✅ |
| **A05 Security Misconfiguration** | `test_owasp_a05_misconfiguration`: missing CSP (CWE-693), Clickjacking (CWE-1021), and CORS wildcard (CWE-942) flagged as A05:2021 ✅ |
| **A06 Vulnerable Components** | `test_owasp_a06_vulnerable_components`: outdated jQuery flagged as A06:2021 (CWE-937, CVSS 6.1) ✅ |
| **A07 Auth Failures** | `test_owasp_a07_auth_failures`: insecure cookies lacking Secure/HttpOnly/SameSite flagged as A07:2021 (CWE-614) ✅ |
| **A08 Software Integrity** | `test_owasp_a08_software_integrity`: external script lacking SRI hash flagged as A08:2021 (CWE-353, CVSS 3.7) ✅ |
| **A09 Logging Failures** | `test_owasp_a09_logging_failures`: missing request tracking (CWE-778) and debug stack trace leak (CWE-209) flagged as A09:2021 ✅ |
| **A10 SSRF** | `test_owasp_a10_ssrf`: unvalidated destination URL parameter flagged as A10:2021 (CWE-918, CVSS 3.9) ✅ |
| **Multi-URL Deduplication** | `test_finding_deduplication_preserves_distinct_urls`: findings on distinct URLs preserved; site-wide headers deduplicated scan-wide ✅ |
| **Findings Lifecycle** | `test_finding_lifecycle_status_transitions`: smooth transitions across open -> confirmed -> in_progress -> resolved -> reopened -> false_positive -> accepted_risk ✅ |
| **User IDOR Protection** | `test_finding_api_idor_protection`: cross-user GET, PATCH, and DELETE requests strictly return 404 Not Found ✅ |
| **Dynamic Posture Calculation** | `test_owasp_summary_reflects_persisted_findings_and_lifecycle`: resolving findings restores posture score from 75 back to 100 and transitions category status from FAIL to PASS ✅ |

---

## 3. Verified Test Results

```
Phase 7 specific tests:    19 / 19 passed  ✅  (backend/tests/test_phase7_owasp_findings.py) in 5.74s
Full backend test suite:  343 / 343 passed  ✅  (100% pass rate, 0 failures)
Frontend production build: 0 TypeScript errors, built in 2.96s ✅
```

---

## 4. Verification Checkpoint Status

### Phase 1
- [x] Backend configuration and environment variables verified
- [x] Python 3.13 and Node.js v25 compatibility confirmed
- [x] Database connectivity to PostgreSQL 16.15 verified
- [x] Alembic migrations upgraded to head (`0011`)
- [x] CORS and security headers active on FastAPI
- [x] Full backend regression tests passed (`267 passed`)
- [x] Backend startup, liveness (`/health`), and readiness (`/readiness`) verified
- [x] Frontend TypeScript typecheck and production build verified (`tsc -b && vite build`)

### Phase 2
- [x] ORM schema drift resolved — `alembic check` clean
- [x] All model relationships correctly wired with `back_populates` and `cascade`
- [x] Repository layer complete — all models have full CRUD
- [x] Service layer complete — IDOR protection on all delete operations
- [x] API layer complete — all missing DELETE endpoints added
- [x] Dashboard notifications endpoint added and tested
- [x] Account deletion with token revocation verified
- [x] 23 Phase 2 regression tests written and passing
- [x] Full suite: 290/290 passed — zero regressions

### Phase 3
- [x] Real frontend/backend API integration across all 10 feature pages
- [x] All 8 Phase 2 endpoints wired into UI components
- [x] Removed remaining mock/fake UI states and hardcoded fallbacks
- [x] Clean zero-state and empty states implemented across all metrics and charts
- [x] Error handling with inline user alerts and retry actions configured
- [x] Route definitions, navigation links, and command search (`ROUTES.PAYLOADS`) verified
- [x] Production build passes cleanly: `tsc -b && vite build` (0 TypeScript errors)
- [x] Frontend linting verified: `oxlint .` (0 warnings, 0 errors on 186 files)
- [x] Full backend regression suite verified: 290 / 290 passed (100%)
- [x] Database migrations verified: `alembic check` clean (0 pending migrations)

### Phase 4
- [x] Crawler module alias map corrected (`"crawler"` → `["crawler", "url_discovery"]`)
- [x] Incremental `modules_json` persistence after each scan stage
- [x] `modules_json` written on `CancelledError` and fatal exception
- [x] SSRF protections verified: RFC1918, loopback, link-local, cloud metadata all blocked
- [x] DNS rebinding interception verified at connection layer (`SafeNetworkBackend`)
- [x] Redirect re-validation verified (max 5 hops, each re-validated)
- [x] TLS enforcement verified (`verify=True`, production mode rejects plain HTTP)
- [x] Response byte cap verified (1 MB ceiling via `SafeHTTPClient.max_response_bytes`)
- [x] Silent `acmecorp.com` fallbacks removed from frontend services and pages
- [x] Frontend `parseModulesJson()` added for truthful module status display
- [x] Frontend Reconnaissance tab wired to real `modules_json` data
- [x] 5 Phase 4 verification tests written and passing
- [x] Full regression suite: 295 / 295 passed — zero regressions
- [x] Frontend production build verified: 0 TypeScript errors, 1.78s build time
- [x] Project documentation (`PROJECT_STATUS.md` and `HANDOVER.md`) updated

### Phase 5
- [x] 1. Security headers analysis module implemented (`SecurityHeadersModule`)
- [x] 2. SSL/TLS observations module implemented (`SslTlsModule`)
- [x] 3. Cookie security attributes module implemented (`CookieSecurityModule`)
- [x] 4. HTTP/HTTPS configuration module implemented (`HttpConfigModule`)
- [x] 5. Redirect analysis module implemented (`RedirectAnalysisModule`)
- [x] 6. Technology fingerprinting module integrated (`TechDetectionModule`)
- [x] 7. robots.txt and sitemap.xml analysis module implemented (`RobotsSitemapModule`)
- [x] 8. Bounded same-origin crawling integrated (`SameOriginCrawlerModule`)
- [x] 9. Endpoint and parameter discovery module implemented (`EndpointParamDiscoveryModule`)
- [x] 10. Publicly exposed configuration checks module implemented (`ExposedConfigCheckerModule`)
- [x] All 10 modules registered in `MODULE_ALIAS_MAP` under `"passive"`, `"headers"`, `"ssl"`, `"crawler"`, and `"recon"` presets
- [x] Every module executes independently in isolated try-except blocks with truthful status recording
- [x] Real findings generated only when backed by actual evidence; secret values redacted from PoC
- [x] Failed/skipped modules report truthful error/skipped statuses; never false success
- [x] Finding deduplication across scans verified (`FindingRepository`)
- [x] 13 Phase 5 verification tests written and passing (`13 / 13 passed` in 11.45s)
- [x] Full regression suite verified: 308 / 308 passed (100% pass rate in 261.21s)
- [x] Frontend production build verified: 0 TypeScript errors, built in 3.02s
- [x] Project documentation (`PROJECT_STATUS.md` and `HANDOVER.md`) updated

### Phase 6
- [x] 1. SQL Injection active detection module implemented (`SQLInjectionDetectorModule`)
  - Harmless single-quote syntax error probes (`'`) for multi-database error signature analysis
  - Arithmetic boolean-differential probes (`1*1` vs `1*0`, `'1'='1` vs `'1'='2'`)
  - Classified as `CONFIRMED` on error patterns or `POTENTIAL` on consistent boolean differentials
- [x] 2. Reflected & safely testable XSS active detection implemented (`XSSDetectorModule`)
  - Harmless unique canary injection (`awasap_xss_<id>`) and safe delimiter reflection testing (`">xss_probe<`)
  - Contextual unencoded HTML reflection analysis without executing arbitrary JavaScript
  - Classified as `CONFIRMED` on unencoded reflection or `POTENTIAL` on DOM sinks & user sources
- [x] 3. CSRF configuration & active validation module implemented (`CSRFDetectorModule`)
  - Identifies state-changing HTML forms (`POST`/`PUT`/`DELETE`) and flags missing anti-CSRF tokens
  - Validates cookie `SameSite` flags and probes cross-origin POST execution without valid tokens
  - Classified as `CONFIRMED` on unprotected state-changing endpoints
- [x] 4. Authentication & session weaknesses module implemented (`SessionAnalyzerModule`)
  - Evaluates session token Shannon entropy and predictability
  - Detects transmission of login credentials over unencrypted cleartext HTTP
  - Actively probes whether authenticated session cookies remain authorized after triggering `/logout`
  - Classified as `CONFIRMED` on cleartext login transmission and logout invalidation failure
- [x] 5. Access control & IDOR indicators module implemented (`IDORDetectorModule`)
  - Catalogs sequential, numeric, and predictable object references
  - Probes controlled lab test IDs and sequential identifier mutations (`999999`)
  - Classified as `CONFIRMED` on accessible cross-user test object IDs without exposing data
- [x] 6. API security misconfigurations module implemented (`APISecurityModule`)
  - Probes HTTP `TRACE` method for Cross-Site Tracing (XST) reflection of credentials
  - Inspects `OPTIONS` response `Allow` headers for dangerous methods (`PUT`, `DELETE`, `DEBUG`)
  - Evaluates rate limiting thresholds using bounded bursts of rapid requests
  - Classified as `CONFIRMED` on active TRACE reflection
- [x] 7. Input validation boundary module implemented (`InputValidationModule`)
  - Probes parameters with safe boundary conditions: type confusion, length boundaries (1,024 reps), null bytes (`%00`)
  - Detects unhandled HTTP 500 Internal Server Errors and stack trace leakage
  - Classified as `CONFIRMED` on reproducible boundary crash responses
- [x] Dual authorization gate enforced: target validation status check + separate `active_confirmed=True` confirmation
- [x] Redaction of sensitive tokens, passwords, and JWTs in proof-of-concept evidence (`[REDACTED]`)
- [x] Preserved all Phase 4 & Phase 5 SSRF protections, connection-layer DNS pinning, TLS verification, and 1 MB response caps
- [x] 16 Phase 6 verification tests written and passing (`16 / 16 passed` in 6.22s)
- [x] Full regression suite verified: 324 / 324 passed (100% pass rate in 262.25s)
- [x] Frontend production build verified: 0 TypeScript errors, built in 2.41s
- [x] Project documentation (`PROJECT_STATUS.md` and `HANDOVER.md`) updated

### Phase 7
- [x] 1. Complete OWASP Top 10 (2021) category mapping across all checkers and scanner modules (A01:2021 through A10:2021)
- [x] 2. Implemented `A09LoggingFailuresChecker` with real checks for missing transaction correlation tracking (CWE-778) and unhandled diagnostic stack trace leakage (CWE-209)
- [x] 3. Corrected canonical CWE and CVSS v3.1 metadata across checkers (e.g. CWE-693 on missing X-Content-Type-Options)
- [x] 4. Fault-isolated category execution in `OWASPEngine` with per-checker error handling
- [x] 5. Scan-aware deduplication in `FindingRepository.create()`: site-wide configurations deduplicate scan-wide while multi-URL vulnerability findings on distinct endpoints are preserved
- [x] 6. End-to-end findings lifecycle supported: `open`, `confirmed`, `in_progress`, `resolved`, `reopened`, `false_positive`, `accepted_risk`
- [x] 7. Backend status validation (`VALID_STATUSES`) and frontend interactive lifecycle transitions via `FindingTable` dropdown
- [x] 8. Dynamic OWASP posture score and category compliance recalculation based on active unresolved findings
- [x] 9. Strict IDOR protection on `GET`, `PATCH`, `DELETE` finding endpoints (404 on cross-user access)
- [x] 10. 19 Phase 7 verification tests written and passing (`19 / 19 passed` in 5.74s)
- [x] Full regression suite verified: 343 / 343 passed (100% pass rate)
- [x] Frontend production build verified: 0 TypeScript errors, built in 2.96s
- [x] Project documentation (`PROJECT_STATUS.md` and `HANDOVER.md`) updated

---

# Phase 8 Handover Documentation — Complete AI Security Chatbot

## Overview

Phase 8 audited, upgraded, and completed the platform's AI Security Chatbot ("Sentinel AI") and remediation engine. Sentinel AI is grounded in verified project architecture and authenticated users' real database records (projects, targets, scans, findings, posture scores, and generated reports). The system features multi-provider abstraction supporting Google Gemini (`gemini-3.5-flash`), OpenAI (`gpt-4o-mini`), and deterministic `MockAIProvider` fallback, strict prompt injection defenses, automated secret/token redaction, sliding-window rate limiting, conversation history bounding, finding-level caching, interactive localStorage session persistence, and explicit separation between verified scanner findings and advisory AI guidance.

---

## 1. Files Created & Modified

| File | Change Summary |
|---|---|
| `backend/app/config.py` | Added `OPENAI_API_KEY` and `effective_openai_api_key` to support dual provider key resolution alongside `effective_gemini_api_key`. |
| `backend/app/schemas/ai.py` | Added contextual fields (`finding_id`, `scan_id`, `target_id`, `report_id`) to `ChatRequest`, enriched `ChatResponse` with provider/model/advisory metadata, and defined `AIStatusOutput`. |
| `backend/app/services/ai/sanitizer.py` | Centralized robust regex sanitizers (`sanitize_sensitive_secrets`, `defend_prompt_injection`, `sanitize_user_input`, `sanitize_evidence_text`) for modular use across service, retriever, and API. |
| `backend/app/services/ai/openai_provider.py` | Fully implemented structured finding analysis, remediation generation, and chat completions via OpenAI `/v1/chat/completions` with JSON mode and fallback. |
| `backend/app/services/ai/gemini_provider.py` | Standardized on active verified `gemini-3.5-flash` model with candidate fallback (`gemini-3.1-flash-lite`, `gemini-3.5-flash-lite`), markdown JSON fence stripping, and graceful mock fallback. |
| `backend/app/services/ai/mock_provider.py` | Explicitly identifies mock engine fallback in `limitations` output and chat responses. |
| `backend/app/services/ai/context_retriever.py` | Enriched context retrieval with user's generated security reports (`Report`), plus targeted fetching methods for specific findings, scans, and reports with automatic secret redaction and prompt injection neutralizing on actual evidence. |
| `backend/app/services/ai/service.py` | Centralized AI chat orchestration, conversation history bounding (max 10 turns), rate limit enforcement, and contextual attachments. |
| `backend/app/api/v1/ai.py` | Upgraded `/chat` to support contextual attachments (`finding_id`, `scan_id`, `target_id`, `report_id`), returned enriched `ChatResponse`, and updated `/status` with full provider readiness metadata. |
| `src/stores/auth-store.ts` | Added automated wipe of all client-side chat conversations (`awasap_sentinel_conversations*`) upon `logout()` to prevent sensitive conversation leakage across accounts. |
| `src/services/findings.service.ts` | Added `ai_explanation_json` and `ai_remediation_json` to `BackendFindingRead` and `normaliseFinding` for instant cached analysis display. |
| `src/services/ai.service.ts` | Added contextual attachment parameters to `sendChatMessage` and updated response types. |
| `src/features/findings/components/finding-detail-view.tsx` | Connected functional "Mark Resolved" status mutation, added "Ask Sentinel AI" deep-link button, and enabled immediate display of cached AI explanations. |
| `src/features/ai-assistant/pages/ai-assistant-page.tsx` | Added user-scoped `localStorage` conversation persistence (`awasap_sentinel_conversations_${user.id}`), URL search param deep-linking (`findingId`, `title`, `query`), advisory notice banner, mock engine fallback badge, and message copy button. |
| `src/types/ai-assistant.ts` | Added `"vulnerability"` category and `findingId` / `scanId` to `Conversation` type. |
| `src/types/finding.ts` | Added `aiExplanationJson` and `aiRemediationJson` to `Finding` interface. |
| `backend/tests/test_phase8_ai_assistant.py` | Comprehensive 20-test suite verifying provider status, finding analysis, remediation, caching, IDOR protection, secret redaction, prompt injection defense, contextual chat, rate limiting, provider fallback, mock identification, and non-destructive finding preservation. |

---

## 2. Tested Security Properties & Safeguards

| Property | Test / Evidence |
|---|---|
| **Status & Readiness** | `test_ai_status_endpoint_returns_readiness_metadata`: reports online status, model, rate limits, and features ✅ |
| **Structured Finding Analysis** | `test_finding_analysis_generates_and_caches_output`: produces summary, risk, impact, why_it_matters, remediation, code, and caches in DB ✅ |
| **Structured Remediation** | `test_generate_remediation_generates_and_caches_output`: produces root cause, recommended fix, steps, verification, and caches in DB ✅ |
| **Tenant Isolation & IDOR** | `test_cross_user_finding_access_is_blocked_with_404`: cross-user analysis and remediation requests strictly return 404 Not Found ✅ |
| **Secret Redaction** | `test_sensitive_secret_redaction`: Bearer tokens, cookies, passwords, API keys, and JWTs are stripped into `[REDACTED]` / `[REDACTED_JWT]` ✅ |
| **Prompt Injection Defense** | `test_prompt_injection_defense`: instruction overrides, jailbreaks, and DAN mode attempts are neutralized to `[BLOCKED_PROMPT_INJECTION_ATTEMPT]` ✅ |
| **Context Retrieval** | `test_context_retriever_gathers_live_user_records`: gathers projects, targets, scans, grouped findings, posture score, and reports ✅ |
| **Targeted Finding Context** | `test_chat_assistant_with_targeted_finding_context`: attaches focused finding metadata to chat prompt context ✅ |
| **Targeted Scan Context** | `test_chat_assistant_with_targeted_scan_context`: attaches focused scan execution metadata to chat prompt context ✅ |
| **Targeted Report Context** | `test_chat_assistant_with_targeted_report_context`: attaches generated report data to chat prompt context ✅ |
| **History Bounding** | `test_conversation_history_bounding`: truncates long conversation histories to max 10 turns to conserve token budget ✅ |
| **Rate Limit Enforcement** | `test_rate_limiting_enforcement`: SlidingWindowRateLimiter strictly blocks exceeding 30 requests/minute with 429 ✅ |
| **OpenAI Provider Fallback** | `test_openai_provider_fallback_when_unconfigured`: gracefully falls back to mock engine when unconfigured or on error ✅ |
| **Gemini Provider Fallback** | `test_gemini_provider_fallback_when_unconfigured`: gracefully falls back to mock engine when unconfigured or on error ✅ |
| **Advisory Distinction** | `test_chat_response_preserves_advisory_distinction`: response flags `is_advisory=True`, distinguishing advice from automated scanner evidence ✅ |

---

## 3. Verified Test Results

```
Phase 8 specific tests:    20 / 20 passed  ✅  (backend/tests/test_phase8_ai_assistant.py) in 8.44s
Combined AI test suite:    26 / 26 passed  ✅  (Phase 8 + test_ai_service.py)
Full backend test suite:  363 / 363 passed  ✅  (100% pass rate in 190.28s, 0 failures)
Frontend production build: 0 TypeScript errors, built in 2.31s ✅
```

---

## 4. Verification Checkpoint Status

### Phase 8 Checklist
- [x] 1. Audited and fixed Google Gemini (`gemini-3.5-flash`) and OpenAI integrations with active models and clean JSON parsing
- [x] 2. Dual provider configuration support (`GEMINI_API_KEY`, `OPENAI_API_KEY`, `AI_API_KEY`) with accurate `/api/v1/ai/status` reporting
- [x] 3. Full integration with authenticated users' real projects, targets, scans, findings, posture score, and generated reports
- [x] 4. Contextual chat attachments for specific finding (`finding_id`), scan (`scan_id`), and report (`report_id`)
- [x] 5. Structured finding analysis (`POST /api/v1/ai/findings/{id}/analyze`) with summary, risk, impact, and secure code snippet
- [x] 6. Structured remediation plan (`POST /api/v1/ai/findings/{id}/remediation`) with root cause, implementation, and verification steps
- [x] 7. Database caching of AI results on finding records (`ai_explanation_json`, `ai_remediation_json`)
- [x] 8. Automated sensitive secret redaction (Bearer tokens, cookies, passwords, API keys, JWTs) on user inputs AND actual retrieved scan evidence
- [x] 9. Prompt injection defenses neutralizing instruction overrides and jailbreak attempts into `[BLOCKED_PROMPT_INJECTION_ATTEMPT]`
- [x] 10. Strict tenant isolation and IDOR protection on finding analysis, remediation, and chat (404 on cross-user access)
- [x] 11. Conversation history bounding (max 10 turns) and sliding-window rate limiting (30 req/min)
- [x] 12. Explicit separation between automated scanner findings and AI-generated advisory recommendations (`is_advisory=True`)
- [x] 13. AI never fabricates findings or modifies verified scanner findings in the database
- [x] 14. Client-side user-scoped conversation isolation (`awasap_sentinel_conversations_${user.id}`) preventing cross-user chat leaks
- [x] 15. Automated client-side chat history wipe on `logout()` preventing post-logout data retention on shared devices
- [x] 16. Mock engine fallback clearly identified in API responses (`limitations` array, notice header) and UI (`MOCK ENGINE (Offline/Fallback)` badge)
- [x] 17. Deep-linking from Finding Detail View ("Ask Sentinel AI") to AI Assistant with pre-populated contextual questions
- [x] 18. Fixed action buttons: "Mark Resolved" finding status mutation with toast feedback and immediate cache display
- [x] 19. 20 Phase 8 verification tests written and passing (`20 / 20 passed`)
- [x] 20. Combined AI test suite verified: 26 / 26 passed (100% pass rate)
- [x] 21. Full regression suite verified: 363 / 363 passed (100% pass rate in 190.28s)
- [x] 22. Frontend production build verified: 0 TypeScript errors, built in 2.31s
- [x] 23. Project documentation (`PROJECT_STATUS.md` and `HANDOVER.md`) updated

---

**Phase 8 Status**: COMPLETE. Standing by for user instruction. Do not start Phase 9 without explicit user approval.

---

# Phase 9 Handover Documentation — Complete Dashboard & Reporting

## Overview
This document records the completion and verification of **Phase 9: Complete Dashboard & Reporting** for the Autonomous Web Application Security Assessment Platform (AWASAP).

---

## 1. Changed & Added Files

| File | Change Description |
|---|---|
| `backend/app/services/report_generator.py` | Added on-demand `format_override` capability, upgraded CSV export with formula injection sanitization and remediation/PoC columns, hardened HTML generator with executive scores, severity breakdown cards, and strict HTML escaping, implemented ReportLab PDF styling, and integrated sensitive secret redaction across all formats. |
| `backend/app/api/v1/reports.py` | Added optional `format` query parameter to `GET /api/v1/reports/{report_id}/download` for dynamic on-demand format conversion, and added dedicated live preview endpoint `GET /api/v1/reports/{report_id}/preview` returning formatted HTML for browser iframe display. |
| `backend/app/services/dashboard.py` | Fixed recent activity classification to distinguish failed/error scans (`"scan_failed"`) from started/completed scans, and expanded activity synthesis to 15 most recent events across scans, findings, and reports. |
| `backend/app/api/v1/dashboard.py` | Hardened `GET /api/v1/dashboard/notifications` to map failed scans and critical/high findings into critical/warning alert cards. |
| `src/services/reports.service.ts` | Updated `downloadReport` to pass `?format=${format}` query param, and configured `getReportContent` to fetch from dedicated `/preview` endpoint. |
| `src/features/reports/pages/reports-page.tsx` | Configured `availableFormats: ["pdf", "html", "json", "csv"]` across all reports. |
| `src/features/reports/components/report-preview-sheet.tsx` | Updated preview sheet to allow direct downloads in any clicked format via `reportsService.downloadReport(report.id, filename, fmt)`. |
| `src/features/reports/components/export-options-bar.tsx` | Connected one-click export cards to download the latest report in the exact clicked format (`pdf`, `html`, `json`, `csv`). |
| `src/features/reports/components/report-history-table.tsx` | Updated dropdown actions to support multi-format exports. |
| `backend/tests/test_phase9_dashboard_reports.py` | Comprehensive 9-test suite verifying dashboard metrics accuracy, activity stream/notifications, 4 export formats, format override, HTML preview, secret redaction, CSV formula injection defense, HTML XSS defense, and cross-user isolation. |
| `docs/PROJECT_STATUS.md` | Documented Phase 9 architecture, metric calculations, export formats, security safeguards, and test results. |
| `docs/HANDOVER.md` | Recorded Phase 9 handover documentation and verification checklist. |

---

## 2. Tested Security Properties & Safeguards

| Property | Test / Evidence |
|---|---|
| **Dashboard Metric Accuracy** | `test_dashboard_summary_accuracy`: verifies real DB counts for projects, targets, scans, findings by severity, score calculation ($100 - (\text{crit}\cdot25 + \text{high}\cdot15 + \text{med}\cdot8)$), and 10 OWASP categories ✅ |
| **Live Activities & Notifications** | `test_dashboard_activities_and_notifications`: verifies synthesis of scan and finding events into typed alert cards (`critical`, `warning`, `info`, `success`) ✅ |
| **All Four Export Formats** | `test_four_report_export_formats`: verifies generation of valid JSON (`application/json`), tabular CSV (`text/csv`), styled HTML (`text/html`), and binary PDF (`%PDF-1.4`) ✅ |
| **Dynamic Format Override** | `test_report_download_format_override`: verifies that requesting `?format=html` on a PDF report generates and returns HTML on demand ✅ |
| **Dedicated HTML Preview** | `test_report_preview_endpoint`: verifies `GET /preview` returns formatted inline HTML for seamless iframe preview without download triggers ✅ |
| **Sensitive Secret Redaction** | `test_secret_redaction_across_report_formats`: verifies Bearer tokens, cookies, passwords, API keys, and JWTs are redacted across JSON, HTML, and CSV exports ✅ |
| **CSV Formula Injection Defense** | `test_csv_formula_injection_defense`: verifies formulas starting with `=`, `+`, `-`, `@`, `%`, or `|` are prefixed with `'` to neutralize DDE execution in Excel/Sheets ✅ |
| **HTML XSS Prevention** | `test_html_xss_defense_in_reports`: verifies raw `<script>` tags and image error payloads in titles, URLs, and descriptions are escaped as `&lt;script&gt;` ✅ |
| **Tenant Isolation & IDOR Protection** | `test_cross_user_isolation_on_reports_and_dashboard`: verifies User B cannot access User A's dashboard metrics (showing 0) or download/preview User A's reports (404 Not Found) ✅ |
| **Inactive Finding Score Handling** | `test_security_score_handles_resolved_false_positive_accepted_risk`: verifies resolved, false-positive, and accepted-risk findings do NOT deduct points from active posture score, while active/reopened findings do ✅ |

---

## 3. Verified Test Results

```
Phase 9 specific tests:    10 / 10 passed  ✅  (backend/tests/test_phase9_dashboard_reports.py) in 3.62s
Dashboard & Reports tests: 15 / 15 passed  ✅  (test_dashboard.py + test_reports.py) in 10.77s
Security hardening tests:  25 / 25 passed  ✅  (test_security_hardening.py) in 4.67s
Full backend test suite:  373 / 373 passed  ✅  (100% pass rate, 0 failures)
Frontend production build: 0 TypeScript errors, built cleanly in 2.85s (tsc -b && vite build) ✅
```

---

## 4. Verification Checkpoint Status

### Phase 9 Checklist
- [x] 1. Verified and hardened live DB-connected dashboard analytics (projects, targets, scans, findings, severity breakdown, OWASP Top 10 distribution, security score)
- [x] 2. Removed all mock and static fallback metrics from dashboard summary calculations
- [x] 3. Verified security score correctly handles resolved, false-positive, and accepted-risk findings without active risk deduction
- [x] 4. Fixed scan status classification in activity stream (`"scan_failed"` for failed/error scans, `"scan_started"`, `"scan_completed"`)
- [x] 5. Implemented real notification aggregation mapping failed scans and critical findings to high-priority alert cards
- [x] 6. Implemented on-demand format override (`?format=...`) enabling any report to be exported as PDF, HTML, JSON, or CSV
- [x] 7. Implemented dedicated live HTML preview endpoint (`GET /api/v1/reports/{id}/preview`) with security headers (`CSP`, `nosniff`)
- [x] 8. Implemented enterprise-grade HTML report design featuring executive score banner, severity summary cards, and formatted evidence blocks
- [x] 9. Implemented CSV formula injection (DDE) protection prepending `'` to sensitive spreadsheet trigger characters (`=`, `+`, `-`, `@`, `\t`, `\r`, `%`, `|`)
- [x] 10. Implemented strict HTML escaping (`html.escape()`) and iframe sandboxing (`sandbox="allow-same-origin allow-modals"`) preventing XSS in preview and reports
- [x] 11. Implemented sensitive secret redaction across all report formats scrubbing Bearer tokens, cookies, passwords, API keys, and JWTs
- [x] 12. Enforced strict tenant isolation and IDOR protection on all dashboard and report routes at the database level (404 on cross-user access)
- [x] 13. Connected frontend `ReportsPage`, `ReportPreviewSheet`, `ExportOptionsBar`, and `ReportHistoryTable` to real backend endpoints
- [x] 14. Verified 10 dedicated Phase 9 tests passing (100% pass rate)
- [x] 15. Verified 15 dashboard and reports regression tests passing (100% pass rate)
- [x] 16. Verified 25 security hardening regression tests passing (100% pass rate)
- [x] 17. Verified full backend regression suite: 373 / 373 passed (100% pass rate)
- [x] 18. Verified frontend production build: 0 TypeScript compilation errors (`tsc -b && vite build`)
- [x] 19. Updated project documentation (`PROJECT_STATUS.md` and `HANDOVER.md`)

---

## 5. Phase 10 Handover — Final Product QA, Security Audit & Deployment

### 5.1 Overview
This section records the final sign-off and completion of **Phase 10: Final Product QA, Security Audit & Deployment** for the Autonomous Web Application Security Assessment Platform (AWASAP).

### 5.2 Verification Checkpoint Status

### Phase 10 Checklist
- [x] 1. Performed complete end-to-end audit across frontend, backend, scanner, AI assistant, reporting, and database tiers
- [x] 2. Verified full product lifecycle E2E flow (`test_full_product_lifecycle_e2e`) passing 100%
- [x] 3. Verified strict cross-user tenant isolation and IDOR protection (`test_unauthorized_and_cross_user_isolation_e2e`) returning 404 on all cross-tenant access attempts
- [x] 4. Verified SSRF, DNS rebinding, private IP, and cloud metadata blocking (`test_ssrf_and_host_validation_protections`)
- [x] 5. Verified scanner cancellation and worker resilience (`test_scanner_cancellation_and_error_resilience`)
- [x] 6. Verified operational health probes (`/health`, `/health/live`, `/readiness`, `/health/ready`) and hardened security headers (`test_operational_health_probes_and_security_headers`)
- [x] 7. Verified Alembic migrations at `0011 (head)` in complete synchronization with ORM models (0 schema drift via `alembic check`)
- [x] 8. Built multi-stage production Dockerfile for backend (`backend/Dockerfile`) with non-root user `appuser` and healthchecks
- [x] 9. Built multi-stage production Dockerfile for frontend (`Dockerfile`) with Node 22-alpine build and Nginx 1.27-alpine runtime
- [x] 10. Configured hardened Nginx reverse proxy (`nginx.conf`) with security headers (CSP, HSTS, nosniff, DENY), gzip, and SPA client routing
- [x] 11. Built unified Docker Compose stack (`docker-compose.yml`) for PostgreSQL 16, FastAPI backend, and Nginx frontend
- [x] 12. Created `.dockerignore` and `backend/.dockerignore` to protect secrets, database files, `.venv`, and node_modules
- [x] 13. Authored master audit deliverable: `docs/FINAL_PRODUCT_AUDIT.md`
- [x] 14. Verified full backend regression test suite: 378 / 378 passed (100% pass rate, 0 failures)
- [x] 15. Verified frontend static linter: `npx oxlint .` passed with 0 warnings and 0 errors across 186 files
- [x] 16. Verified frontend production build: `tsc -b && vite build` built cleanly with 0 TypeScript compilation errors
- [x] 17. Updated `docs/PROJECT_STATUS.md` and `docs/HANDOVER.md`

### 5.3 Automated Test Metrics Summary

```
Phase 10 E2E tests:        5 / 5 passed    ✅  (backend/tests/test_phase10_final_qa.py) in 18.18s
Phase 9 reports tests:     10 / 10 passed  ✅  (backend/tests/test_phase9_dashboard_reports.py) in 3.62s
Dashboard & Reports tests: 15 / 15 passed  ✅  (test_dashboard.py + test_reports.py)
Security hardening tests:  25 / 25 passed  ✅  (test_security_hardening.py)
Phase 8 AI tests:          20 / 20 passed  ✅  (test_phase8_ai_assistant.py)
Phase 7 OWASP tests:       19 / 19 passed  ✅  (test_phase7_owasp_engine.py)
Phase 6 Scanner tests:     16 / 16 passed  ✅  (test_phase64_step3_integration.py)
Full backend test suite:   378 / 378 passed ✅  (100% pass rate, 0 failures) in 4m 50s
Frontend static linter:    0 warnings, 0 errors across 186 files (npx oxlint .) ✅
Frontend production build: 0 TypeScript errors, built cleanly in 3.32s (tsc -b && vite build) ✅
Database migration check:  0011 (head), "No new upgrade operations detected" (zero drift) ✅
```

---

**FINAL PLATFORM STATUS**: COMPLETE & FULLY VERIFIED.
The AWASAP platform is 100% complete, fully audited, tested, and ready for production deployment. All 10 phases are officially closed.

---

## 6. Manual URL Scanner — Grand Master Fix Handover

### 6.1 Summary of Changes
The Manual URL Scanner Grand Master Fix eliminates the issue where manual target URLs entered by the user were overridden by seeded benchmark targets (`http://testphp.vulnweb.com`) or stale targets.

### 6.2 Key Deliverables Completed
1. **Frontend Input & State Synchronization**:
   - `src/features/scans/components/scan-config-panel.tsx`: Typing a custom URL immediately clears any stale registered target ID selection. Clean distinction between registered library targets and custom manual targets.
   - `src/features/scans/hooks/use-scan-engine.ts`: `resetScan()` now resets target state (`selectedTargetId = ""`, `selectedProjectId = ""`, `selectedTargetUrl = ""`), preventing stale target reuse. `startScan()` verifies target URL matching and passes `targetUrl` in the payload.
   - `src/services/scans.service.ts`: Fixed `getOrCreateTargetForUrl()` to re-throw backend 400 validation and SSRF errors directly without swallowing them. Added `createDirectScan()`.
   - `src/features/scans/components/new-scan-dialog.tsx`: Propagates explicit `targetUrl` and `targetId`.
2. **Backend API & Service Alignment**:
   - `backend/app/schemas/scan.py`: Added `target_url`, `target_id`, and `project_id` to `ScanCreateRequest`.
   - `backend/app/api/v1/scans.py`: Added `POST /api/v1/scans` (direct scan creation route).
   - `backend/app/services/scan.py`: Added `create_direct_scan()`; updated `create_scan()` to align the target if an explicit URL is provided.
   - `backend/app/services/target.py`: Updated `_normalize_url()` to reject unsupported schemes (`ftp://`), embedded credentials, cloud metadata hostnames, and private/loopback IPs.
   - `backend/app/services/scanner_engine.py`: Replaced raw `target_url` with `validated_url` across all modules (`HttpConfigModule`, `RedirectAnalysisModule`).
   - `backend/app/services/report_generator.py`: Updated `_generate_json()` to include `target_url`.
3. **Comprehensive Regression Testing**:
   - Authored `backend/tests/test_manual_url_scanner.py` with 5 automated test cases.
   - Verified real network dispatch to two isolated, controlled local HTTP servers (Server A on Port X, Server B on Port Y), confirming that scanning Server A sends requests ONLY to A (0 to B), and scanning Server B sends requests ONLY to B (0 to A).
   - Verified that invalid schemes, credentials, and SSRF private/metadata addresses fail safely with 400 Bad Request.

### 6.3 Test Verification Results
- **Manual URL Scanner Suite**: 5 / 5 passed (`backend/tests/test_manual_url_scanner.py`)
- **Focused Suite**: 31 / 31 passed (`test_scans.py`, `test_targets.py`, `test_e2e_scanner_flow.py`, `test_reports.py`, `test_manual_url_scanner.py`)
- **Full Backend Regression Suite**: 383 / 383 passed (100% pass rate) in 3m 44s
- **TypeScript Check**: `pnpm exec tsc -b` passed with 0 errors
- **Frontend Production Build**: `pnpm run build` (`tsc -b && vite build`) built cleanly in 14.85s

---

## 7. Dashboard Crash Root Cause Fix Handover

### 7.1 Summary of Incident & Fix
The dashboard crash with `Cannot read properties of undefined (reading 'icon')` at `recent-activity.tsx:108` occurred whenever a user had a failed or cancelled scan in their activity history. The backend synthesizes `type: "scan_failed"` for failed scans, but `TYPE_CONFIG` in `recent-activity.tsx` only had keys for 5 event types, leaving `"scan_failed"` as `undefined` and causing a runtime crash on `.icon`.

### 7.2 Remediations Applied
1. **Activity Type Mapping (`src/features/dashboard/components/recent-activity.tsx`)**:
   - Registered all 11 activity types (`scan_completed`, `scan_failed`, `scan_cancelled`, `scan_started`, `scan_running`, `scan_queued`, `finding_discovered`, `finding_resolved`, `report_generated`, `target_created`, `project_created`) with explicit icons, labels, and styling.
   - Added `DEFAULT_CONFIG` with `Activity` icon as a safe fallback; never accesses `.icon` on `undefined`.
   - Added safe timestamp parsing and category prefix filtering (`scan_`, `finding_`, `report_`).
2. **Defensive Audit Across Components**:
   - `src/features/dashboard/components/severity-badge.tsx`: Added case normalization and fallback to `severityConfig.info` for unknown/null severities.
   - `src/features/dashboard/components/recent-scan-card.tsx`: Guarded against null/empty scan IDs and undefined statuses.
   - `src/features/dashboard/data/dashboard-data.ts`: Extended `ActivityType` union and `ActivityItem` interface.
   - `src/services/dashboard.service.ts`: Widened activity type from strict enum to string.
   - `backend/app/services/dashboard.py`: Added explicit `"scan_cancelled"` status mapping.
3. **Automated Regression Suites**:
   - Backend: Added `test_dashboard_activity_types_and_resilience` in `backend/tests/test_dashboard.py` (6 / 6 passed).
   - Frontend: Created `scripts/test-dashboard-components.tsx` and `pnpm run test:dashboard` (7 / 7 passed).
   - TypeScript: `pnpm exec tsc -b` (0 errors).
   - Production Build: `pnpm run build` (`tsc -b && vite build`) (built cleanly in 1.90s).



