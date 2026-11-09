# AWASAP Security Payloads Dataset Integration Guide

## 1. Overview & Architecture

This document details the architecture and operational guidelines for integrating the **Web Application Payloads Dataset** into the **AWASP** (Autonomous Web Application Security Assessment Platform).

The integration persists curated vulnerability test signatures into PostgreSQL and exposes them safely through:
- **Backend**: FastAPI with async SQLAlchemy 2.0 ORM, asyncpg, and Alembic migrations.
- **Database**: PostgreSQL table `security_payloads` with indexes on primary key, category type, and severity.
- **API**: REST endpoints for paginated browsing, filtering, search, and aggregate metrics.
- **Frontend**: React 19 + TypeScript + Vite dashboard page with safe text escaping (payloads are never executed in the browser).
- **Scanner Engine**: Safe, rate-limited test probes governed by strict SSRF guardrails and non-destructive policies.

---

## 2. Dataset Schema & Quality Report

### 2.1 File Inventory
- `dataset/WEB_APPLICATION_PAYLOADS.jsonl` — Original source backup preserved unmodified.
- `dataset/WEB_APPLICATION_PAYLOADS_fixed.json` — 500 records.
- `dataset/WEB_APPLICATION_PAYLOADS_valid.json` — 499 validated records used for import.
- `dataset/invalid_records.json` — Audit report of records failing validation.

### 2.2 Data Quality & Exclusion of `csrf-039`
During dataset pre-flight analysis, record `csrf-039` was identified as incomplete:
- **Issue**: The `payload` field was missing because the payload text was accidentally merged into the `description` string in the upstream source.
- **Handling Policy**: Pursuant to strict data integrity rules, no missing payload was fabricated or hallucinated. `csrf-039` was excluded from the database import and formally recorded in `dataset/invalid_records.json`:
```json
[
  {
    "id": "csrf-039",
    "reason": "Missing required field: payload (description text contained merged JavaScript call without explicit payload field)",
    "context": "CSRF test suite",
    "type": "CSRF",
    "severity": "high",
    "excluded_from_import": true
  }
]
```

### 2.3 Field Mapping
| Source Field | DB Column | Type | Constraints | Description |
|---|---|---|---|---|
| `id` | `id` | `VARCHAR(64)` | `PRIMARY KEY`, indexed | Stable identifier (e.g. `sqli-001`, `cmdinj-100`) |
| `description` | `description` | `TEXT` | `NOT NULL` | Human-readable explanation of attack vector |
| `payload` | `payload` | `TEXT` | `NOT NULL` | Exact raw payload text preserved verbatim |
| `context` | `context` | `TEXT` | `NOT NULL` | Injection context (e.g. "Login form", "Search parameter") |
| `type` | `type` | `VARCHAR(64)` | `NOT NULL`, indexed | Vulnerability category or subtype |
| `severity` | `severity` | `VARCHAR(32)` | `NOT NULL`, indexed | Validated level: `critical`, `high`, `medium`, `low`, `info` |
| `example_usage` / `example_query` | `example_usage` | `TEXT` | `NULLABLE` | Optional contextual query or sample request |
| Generated | `created_at` | `TIMESTAMPTZ` | `NOT NULL`, default `now()` | Timestamp of insertion |
| Generated | `updated_at` | `TIMESTAMPTZ` | `NOT NULL`, default `now()` | Timestamp of last modification |

---

## 3. Database Migration & Importer

### 3.1 Migration
Alembic migration revision `0009` (`backend/alembic/versions/0009_create_security_payloads.py`) creates table `security_payloads` with composite and single-column indexes:
- `ix_security_payloads_id`
- `ix_security_payloads_type`
- `ix_security_payloads_severity`
- `ix_security_payloads_type_severity`

Run migration:
```bash
cd backend
alembic upgrade head
```

### 3.2 Idempotent Importer Command
To import or re-synchronize payloads from the dataset:
```bash
cd backend
python -m app.scripts.import_payloads
```
Options:
- `--file <path>`: Custom dataset path (default: `dataset/WEB_APPLICATION_PAYLOADS_valid.json`).
- `--no-update`: Skip updating existing records if remote definitions differ.

**Idempotency Guarantee**:
- Running the script against an empty table inserts 499 rows.
- Running the script a second time detects identical existing rows and skips all 499 rows without creating duplicates.
- All operations run within an explicit transactional boundary with automatic rollback upon any error.

### 3.3 Database Verification
To inspect record counts and distribution directly in PostgreSQL:
```bash
cd backend
python -m app.scripts.verify_db
```
Current PostgreSQL distribution:
- **Total Valid Payloads**: 499
- **Severities**: High (261), Medium (151), Critical (75), Low (12)
- **Categories**: SSRF (100), Command Injection (100), CSRF (99), Reflected XSS (54), Stored XSS (46), Blind-Time SQLi (33), Tautology SQLi (19), Union SQLi (19), Boolean-Blind SQLi (13), Stacked Queries (12), Error-Based SQLi (4)

---

## 4. API Endpoints

All endpoints are mounted under `/api/v1/payloads` and require bearer token authentication (`Authorization: Bearer <token>`).

### 4.1 `GET /api/v1/payloads`
Retrieve paginated list of security payloads with server-side filtering and search.
- **Query Parameters**:
  - `page`: Page number (default: 1, `ge=1`).
  - `page_size`: Records per page (default: 20, `ge=1`, `le=100`).
  - `type`: Filter by vulnerability type/category (e.g., `SSRF`, `reflected`, `tautology`).
  - `severity`: Filter by severity (`critical`, `high`, `medium`, `low`, `info`).
  - `q`: Free-text search matching `id`, `description`, `payload`, `context`, or `type`.
- **Response** (`200 OK`):
```json
{
  "items": [
    {
      "id": "sqli-001",
      "description": "Basic tautology-based SQL injection",
      "payload": "' OR '1'='1",
      "context": "Login form username input",
      "type": "tautology",
      "severity": "high",
      "example_usage": "SELECT * FROM users WHERE username = '' OR '1'='1' AND password = ''",
      "created_at": "2026-10-09T15:26:29.506363Z",
      "updated_at": "2026-10-09T15:26:29.506363Z"
    }
  ],
  "total": 499,
  "page": 1,
  "page_size": 20,
  "total_pages": 25
}
```

### 4.2 `GET /api/v1/payloads/stats`
Retrieve aggregated statistics across categories and severity levels.
- **Response** (`200 OK`):
```json
{
  "total": 499,
  "by_severity": {
    "critical": 75,
    "high": 261,
    "medium": 151,
    "low": 12
  },
  "by_type": {
    "SSRF": 100,
    "Command Injection": 100,
    "CSRF": 99,
    "reflected": 54,
    "stored": 46,
    ...
  }
}
```

### 4.3 `GET /api/v1/payloads/{payload_id}`
Retrieve complete details for a single payload record.
- **Response** (`200 OK`): `SecurityPayloadRead` object.
- **Error** (`404 Not Found`): If the specified ID does not exist in the database.

---

## 5. Frontend Integration

- **Route**: Accessible at `/payloads` within the authenticated dashboard layout.
- **Navigation**: Added under the "Main" menu as **Payloads** with a Database icon.
- **Features**:
  - Live metric cards (Total Payloads, Critical, High, Categories).
  - Search bar across ID, description, and payload strings.
  - Dropdown filters for category and severity.
  - Paginated table with responsive pagination controls.
  - "Inspect" drawer/modal to view complete payload, context, and example query.
  - "Copy Payload" button with clipboard integration and Sonner toast feedback.
- **Security Protections**:
  - Payloads are displayed strictly inside preformatted `<pre>` and `<code>` blocks with string escaping.
  - Payloads are **never** evaluated or injected as raw HTML/DOM elements in the browser.

---

## 6. Scanner Integration & Security Guardrails

The payload library is integrated via `PayloadSecurityTestRunner` (`backend/app/services/scanner/payload_test_runner.py`) adhering to the following rules:

1. **Explicit Target Authorization**: Probes are executed only against target URLs belonging to the user's active, verified project scan.
2. **SSRF Guardrails**: Every target URL is validated via `app.core.ssrf.validate_target_url()`. Outbound connections to loopback (`127.0.0.1`), RFC1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud metadata (`169.254.169.254`), and multicast addresses are rejected immediately.
3. **No Local Execution**: OS command injection and shell payloads are treated strictly as data strings passed to remote HTTP parameters. They are **never executed on the host system**.
4. **Non-Destructive Probe Policy**: Payloads containing destructive tokens (`drop database`, `rm -rf`, `format`) are blocked or substituted with benign probes.
5. **Detection Confidence Classification**:
   - `CONFIRMED`: Definitive indicator returned by target (e.g., database engine syntax error disclosing the payload, unescaped reflection inside script tag).
   - `SUSPECTED`: Target returned anomalous behavior or HTTP 500 error on the injected parameter.
   - `INCONCLUSIVE`: Normal response, rate limit, timeout, or blocked by WAF.

---

## 7. Operational Run Guide

### 7.1 Backend
```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
Interactive Swagger documentation is available at `http://localhost:8000/docs`.

### 7.2 Frontend
```bash
# from root directory
pnpm dev
```
Accessible at `http://localhost:5173`.

### 7.3 Running Tests
Run the entire backend test suite:
```bash
cd backend
pytest
```
Run payload-specific test suite:
```bash
cd backend
pytest tests/test_payloads.py -v
```
Build and verify the frontend:
```bash
pnpm run build
```
