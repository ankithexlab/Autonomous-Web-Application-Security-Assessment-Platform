"""
Mock AI Provider implementation.

Provides deterministic zero-cost security analysis for testing and offline development.
"""

from app.schemas.ai import AIAnalysisInput, AIAnalysisOutput, AIRemediationOutput, ChatMessageInput
from app.services.ai.base import BaseAIProvider


class MockAIProvider(BaseAIProvider):
    async def analyze_finding(self, input_data: AIAnalysisInput) -> AIAnalysisOutput:
        title = input_data.title
        severity = input_data.severity.lower()

        remediation_steps = [
            f"Review input validation and sanitization for {title}.",
            "Enforce strict Content Security Policy (CSP) and CORS origin restrictions.",
            "Use context-aware output encoding or parameterized database queries.",
        ]

        if "header" in title.lower() or "cors" in title.lower():
            secure_code = (
                "// Nginx Security Headers Configuration\n"
                "add_header Content-Security-Policy \"default-src 'self'\";\n"
                "add_header X-Frame-Options \"DENY\";\n"
                "add_header X-Content-Type-Options \"nosniff\";"
            )
        elif "sql" in title.lower():
            secure_code = (
                "// Python SQLAlchemy Parameterized Query\n"
                "stmt = select(User).where(User.username == username)\n"
                "result = await session.execute(stmt)"
            )
        else:
            secure_code = (
                "// Secure Implementation Example\n"
                "function sanitizeInput(input: string): string {\n"
                "  return encodeURIComponent(input.trim());\n"
                "}"
            )

        return AIAnalysisOutput(
            summary=f"Automated AI Analysis for '{title}': Identifies potential {severity} risk.",
            risk_explanation=f"The vulnerability '{title}' exposes application resources to unauthorized manipulation or disclosure.",
            impact=f"High impact on confidentiality and integrity if exploited on {input_data.affected_url or 'target endpoint'}.",
            why_it_matters="Securing this vector is critical to maintaining OWASP compliance and defense-in-depth.",
            remediation_guidance=remediation_steps,
            secure_code_example=secure_code,
            confidence=input_data.confidence.upper() if input_data.confidence else "HIGH",
            limitations=[
                "Analysis performed based on passive HTTP response evidence and OWASP rule checks.",
                "Generated using offline deterministic mock security engine (fallback).",
            ],
        )

    async def generate_remediation(self, input_data: AIAnalysisInput) -> AIRemediationOutput:
        title = input_data.title.lower()

        if "header" in title or "csp" in title or "x-frame" in title:
            return AIRemediationOutput(
                remediation_summary="Configure missing HTTP security headers to enforce browser-level defense in depth.",
                root_cause="The web server is not setting defensive HTTP headers, leaving clients vulnerable to clickjacking or MIME-sniffing.",
                recommended_fix="Add X-Frame-Options, X-Content-Type-Options, and Content-Security-Policy to web server or application middleware.",
                implementation_steps=[
                    "Configure Nginx / FastAPI middleware to inject security headers on all outgoing responses.",
                    "Verify header presence using browser developer tools or curl -I.",
                    "Deploy changes to staging and verify application compatibility.",
                ],
                secure_configuration_example=(
                    "# Nginx Header Configuration\n"
                    "add_header Content-Security-Policy \"default-src 'self'\";\n"
                    "add_header X-Frame-Options \"DENY\";\n"
                    "add_header X-Content-Type-Options \"nosniff\";\n"
                    "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";"
                ),
                secure_code_example=(
                    "# FastAPI Middleware Security Headers\n"
                    "@app.middleware('http')\n"
                    "async def add_security_headers(request: Request, call_next):\n"
                    "    response = await call_next(request)\n"
                    "    response.headers['X-Frame-Options'] = 'DENY'\n"
                    "    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
                    "    return response"
                ),
                affected_component="Web Server Response Headers / Middleware",
                verification_steps=[
                    "Run a follow-up scan or issue: curl -I https://target.example.com",
                    "Verify HTTP 200 responses contain X-Frame-Options and X-Content-Type-Options headers.",
                ],
                limitations=[
                    "Header enforcement requires web server reload or application restart.",
                    "Generated using offline deterministic mock security engine (fallback).",
                ],
                confidence="HIGH",
            )
        elif "sql" in title or "database" in title or "injection" in title:
            return AIRemediationOutput(
                remediation_summary="Use parameterized SQL queries and ORM prepared statements to eliminate SQL Injection.",
                root_cause="Dynamic string formatting or string concatenation was used when building database queries.",
                recommended_fix="Replace raw SQL string concatenation with SQLAlchemy bound parameters.",
                implementation_steps=[
                    "Locate queries using raw string formatting.",
                    "Replace raw SQL calls with SQLAlchemy select statements and bound parameters.",
                    "Execute unit test suite to verify query correctness.",
                ],
                secure_code_example=(
                    "# Secure SQLAlchemy Query Implementation\n"
                    "stmt = select(User).where(User.username == username)\n"
                    "result = await session.execute(stmt)\n"
                    "user = result.scalar_one_or_none()"
                ),
                affected_component="Database Access Layer / SQLAlchemy Repository",
                verification_steps=[
                    "Run parameterized query unit tests.",
                    "Execute passive scan to verify input field sanitization.",
                ],
                limitations=[
                    "Requires code refactoring in database repository methods.",
                    "Generated using offline deterministic mock security engine (fallback).",
                ],
                confidence="HIGH",
            )
        else:
            return AIRemediationOutput(
                remediation_summary=f"Remediation guidance for '{input_data.title}'.",
                root_cause="Defensive input sanitization or configuration setting missing.",
                recommended_fix="Implement strict validation, least-privilege policies, and contextual output encoding.",
                implementation_steps=[
                    "Validate all incoming request parameters.",
                    "Apply contextual encoding before rendering output.",
                    "Enforce strict server-side authorization controls.",
                ],
                secure_code_example=(
                    "# Secure Input Validation Pattern\n"
                    "from pydantic import BaseModel, Field\n\n"
                    "class RequestPayload(BaseModel):\n"
                    "    query: str = Field(min_length=1, max_length=255)"
                ),
                affected_component="Application Business Logic / API Route Handler",
                verification_steps=[
                    "Execute automated test suite.",
                    "Re-run security scanner against updated target URL.",
                ],
                limitations=[
                    "Remediation guidance should be verified by developers in staging environments.",
                    "Generated using offline deterministic mock security engine (fallback).",
                ],
                confidence="HIGH",
            )

    async def chat_completion(
        self,
        messages: list[ChatMessageInput],
        system_instruction: str | None = None,
    ) -> str:
        last_msg = messages[-1].content.lower() if messages else ""

        if "what is awasap" in last_msg or "modules are actually implemented" in last_msg:
            return (
                "### AWASAP Platform Architecture\n\n"
                "**AWASAP** (Autonomous Web Application Security Assessment Platform) is an automated web security "
                "platform designed to scan web targets, audit vulnerabilities, and provide AI-guided remediation.\n\n"
                "**Implemented Core Modules:**\n"
                "- **Scanner Engine (`backend/app/services/scanner_engine.py`)**: 10-stage passive security auditor with SSRF protection.\n"
                "- **Reconnaissance & Gathering**: DNS (`dns_lookup.py`), WHOIS (`whois_lookup.py`), IP & ASN (`ip_detection.py`), Tech detection (`tech_detection.py`), and Directory discovery (`directory_discovery.py`).\n"
                "- **Auditors**: Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), Cookie flags (HttpOnly, Secure, SameSite), HTTPS & redirect chains, and Server banner disclosure.\n"
                "- **OWASP Engine (`backend/app/services/owasp/owasp_engine.py`)**: Passive checks for OWASP Top 10 (A01 - A10).\n"
                "- **Vulnerability Detectors**: SQLi, XSS, CSRF, IDOR, Open Redirect, Command Injection, JWT, API Security, File Upload, Rate Limiting, and Payload Testing.\n"
                "- **Dashboard Operations**: Real-time vulnerability aggregation and risk posture score calculation.\n"
                "- **Payload Dataset (`backend/app/models/security_payload.py`)**: Standardized security test signatures.\n"
                "- **Sentinel AI Assistant**: Google Gemini-powered security chatbot."
            )
        elif "where is the scanner engine" in last_msg or "scanner engine implemented" in last_msg:
            return (
                "### AWASAP Scanner Engine Architecture\n\n"
                "The core scanner engine is implemented in:\n"
                "- **Primary Controller**: [`backend/app/services/scanner_engine.py`](file:///backend/app/services/scanner_engine.py)\n"
                "- **Execution Method**: `ScannerEngine.run_scan(scan_id: UUID)`\n"
                "- **HTTP Client with SSRF Protection**: [`backend/app/core/http_client.py`](file:///backend/app/core/http_client.py) and [`backend/app/core/ssrf.py`](file:///backend/app/core/ssrf.py)\n\n"
                "**Scanning Pipeline (10 Sequential Stages):**\n"
                "1. **Stage 1 (5%)**: Target URL validation & SSRF check (blocks private & cloud metadata IPs).\n"
                "2. **Stage 2 (15%)**: Passive info gathering (DNS, WHOIS, IP, Tech detection).\n"
                "3. **Stage 3 (30%)**: Primary HTTP response collection.\n"
                "4. **Stage 4 (45%)**: Security headers & cookie security audit.\n"
                "5. **Stage 5 (55%)**: HTTPS enforcement & redirect chain analysis.\n"
                "6. **Stage 6 (65%)**: Server header disclosure & robots.txt/sitemap.xml check.\n"
                "7. **Stage 7 (75%)**: OWASP Top 10 checks.\n"
                "8. **Stage 8 (85%)**: Security analysis (CORS & session management).\n"
                "9. **Stage 9 (95%)**: Vulnerability detection modules (SQLi, XSS, CSRF, IDOR, etc.).\n"
                "10. **Stage 10 (100%)**: Summary metric compilation & status completion."
            )
        elif "security score" in last_msg or "100/100" in last_msg or "posture score" in last_msg:
            return (
                "### AWASAP Security Posture Score Calculation\n\n"
                "The security score is calculated dynamically in [`backend/app/services/dashboard.py`](file:///backend/app/services/dashboard.py) (lines 83-84):\n\n"
                "```python\n"
                "deduction = critical_cnt * 25 + high_cnt * 15 + medium_cnt * 8 + low_cnt * 3\n"
                "score = max(0.0, float(100 - deduction))\n"
                "```\n\n"
                "**Why your dashboard shows 100/100:**\n"
                "- The security score starts at **100.0**.\n"
                "- Each **Critical** finding deducts **25 points**.\n"
                "- Each **High** finding deducts **15 points**.\n"
                "- Each **Medium** finding deducts **8 points**.\n"
                "- Each **Low** finding deducts **3 points**.\n"
                "- **Informational** findings cause **0 points** deduction.\n\n"
                "If no scans have been performed yet, or if all scans completed with 0 vulnerabilities detected, the deduction is `0`, resulting in a perfect **100/100** score."
            )
        elif "sql" in last_msg or "injection" in last_msg:
            return (
                "### SQL Injection Remediation Strategy\n\n"
                "SQL Injection occurs when untrusted user input is concatenated into database queries.\n\n"
                "**Remediation Steps:**\n"
                "1. **Use Parameterized Queries / Prepared Statements:** Always bind variables.\n"
                "2. **Use ORM Abstractions:** Leverage SQLAlchemy or Prisma.\n"
                "3. **Apply Principle of Least Privilege:** Restrict DB user capabilities.\n\n"
                "```python\n"
                "# Secure Query\n"
                "stmt = select(User).where(User.email == user_email)\n"
                "```"
            )
        elif "ssrf" in last_msg or "server-side" in last_msg:
            return (
                "### Server-Side Request Forgery (SSRF) Defense\n\n"
                "SSRF occurs when an application fetches remote resources without validating destination IP addresses.\n\n"
                "**Defense Mechanism in AWASAP:**\n"
                "- In AWASAP, [`backend/app/core/ssrf.py`](file:///backend/app/core/ssrf.py) resolves hostnames and validates destination host IP addresses against private IP blacklists (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `169.254.169.254`).\n"
                "- It prevents the scanner from accessing cloud metadata services or internal microservices."
            )
        else:
            return (
                "### Sentinel AI Security Assistant\n\n"
                "I am Sentinel AI, the cybersecurity assistant for the AWASAP platform.\n\n"
                "I can assist you with:\n"
                "- Explaining AWASAP's architecture, scanner engine, and modules.\n"
                "- Reviewing your scan results, findings, and posture score.\n"
                "- Technical remediation guidance for SQLi, XSS, CSRF, SSRF, and security headers.\n"
                "- Auditing secure code patterns and configuration snippets."
            )
