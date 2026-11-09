"""
Technology Detection Scanner Module.

Passive technology fingerprinting from HTTP response headers, HTML content,
cookies, and JavaScript library patterns. Identifies web frameworks, CMS,
programming languages, and client-side libraries.
"""

import re
from typing import Any

from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.models.scan import Scan
from app.services.scanner.base_module import BaseScannerModule

# ── Fingerprint Databases ───────────────────────────────────────────

HEADER_FINGERPRINTS: list[dict[str, str]] = [
    {"header": "x-powered-by", "pattern": "php", "name": "PHP", "category": "Programming Language"},
    {"header": "x-powered-by", "pattern": "asp.net", "name": "ASP.NET", "category": "Framework"},
    {"header": "x-powered-by", "pattern": "express", "name": "Express.js", "category": "Framework"},
    {"header": "x-powered-by", "pattern": "next.js", "name": "Next.js", "category": "Framework"},
    {"header": "x-powered-by", "pattern": "nuxt", "name": "Nuxt.js", "category": "Framework"},
    {"header": "x-powered-by", "pattern": "servlet", "name": "Java Servlet", "category": "Framework"},
    {"header": "x-generator", "pattern": "wordpress", "name": "WordPress", "category": "CMS"},
    {"header": "x-generator", "pattern": "drupal", "name": "Drupal", "category": "CMS"},
    {"header": "x-drupal-cache", "pattern": "", "name": "Drupal", "category": "CMS"},
    {"header": "x-aspnet-version", "pattern": "", "name": "ASP.NET", "category": "Framework"},
    {"header": "x-aspnetmvc-version", "pattern": "", "name": "ASP.NET MVC", "category": "Framework"},
]

COOKIE_FINGERPRINTS: list[dict[str, str]] = [
    {"pattern": "phpsessid", "name": "PHP", "category": "Programming Language"},
    {"pattern": "jsessionid", "name": "Java", "category": "Programming Language"},
    {"pattern": "asp.net_sessionid", "name": "ASP.NET", "category": "Framework"},
    {"pattern": "csrftoken", "name": "Django", "category": "Framework"},
    {"pattern": "laravel_session", "name": "Laravel", "category": "Framework"},
    {"pattern": "rack.session", "name": "Ruby on Rails", "category": "Framework"},
    {"pattern": "_rails_session", "name": "Ruby on Rails", "category": "Framework"},
    {"pattern": "connect.sid", "name": "Express.js", "category": "Framework"},
    {"pattern": "wp-settings", "name": "WordPress", "category": "CMS"},
]

HTML_FINGERPRINTS: list[dict[str, str]] = [
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress', "name": "WordPress", "category": "CMS"},
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', "name": "Joomla", "category": "CMS"},
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal', "name": "Drupal", "category": "CMS"},
    {"pattern": r'wp-content/', "name": "WordPress", "category": "CMS"},
    {"pattern": r'wp-includes/', "name": "WordPress", "category": "CMS"},
    {"pattern": r'/sites/default/files/', "name": "Drupal", "category": "CMS"},
]

JS_LIBRARY_FINGERPRINTS: list[dict[str, str]] = [
    {"pattern": r"jquery[.-](\d+\.\d+\.\d+)", "name": "jQuery", "category": "JavaScript Library"},
    {"pattern": r"react[.-]dom", "name": "React", "category": "JavaScript Library"},
    {"pattern": r"angular[./]", "name": "Angular", "category": "JavaScript Library"},
    {"pattern": r"vue[./]", "name": "Vue.js", "category": "JavaScript Library"},
    {"pattern": r"bootstrap[.-](\d+\.\d+)", "name": "Bootstrap", "category": "CSS Framework"},
    {"pattern": r"tailwindcss", "name": "Tailwind CSS", "category": "CSS Framework"},
    {"pattern": r"font-awesome", "name": "Font Awesome", "category": "Icon Library"},
    {"pattern": r"lodash", "name": "Lodash", "category": "JavaScript Library"},
    {"pattern": r"moment[.-](\d+\.\d+)", "name": "Moment.js", "category": "JavaScript Library"},
    {"pattern": r"axios", "name": "Axios", "category": "JavaScript Library"},
    {"pattern": r"gsap", "name": "GSAP", "category": "Animation Library"},
    {"pattern": r"three\.js|three\.module", "name": "Three.js", "category": "JavaScript Library"},
]


class TechDetectionModule(BaseScannerModule):
    module_id = "tech_detection"
    module_name = "Technology Detection"
    category = "Information Gathering"

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        if not main_resp:
            return {"technologies": []}

        detected: list[dict[str, str]] = []
        seen_names: set[str] = set()

        def _add(name: str, category: str, version: str = "", confidence: str = "HIGH") -> None:
            if name not in seen_names:
                seen_names.add(name)
                detected.append({
                    "name": name,
                    "category": category,
                    "version": version,
                    "confidence": confidence,
                })

        headers = main_resp.headers
        body = main_resp.text or ""

        # ── 1. Header-based fingerprinting ──────────────────────────
        for fp in HEADER_FINGERPRINTS:
            header_val = headers.get(fp["header"], "").lower()
            if header_val and (not fp["pattern"] or fp["pattern"] in header_val):
                version = header_val.replace(fp["pattern"], "").strip(" /")
                _add(fp["name"], fp["category"], version)

        # Server header
        server = headers.get("server", "")
        if server:
            _add(server.split("/")[0], "Web Server", server.split("/")[-1] if "/" in server else "")

        # ── 2. Cookie-based fingerprinting ──────────────────────────
        set_cookie = headers.get("set-cookie", "").lower()
        for fp in COOKIE_FINGERPRINTS:
            if fp["pattern"] in set_cookie:
                _add(fp["name"], fp["category"])

        # ── 3. HTML meta tag fingerprinting ─────────────────────────
        for fp in HTML_FINGERPRINTS:
            match = re.search(fp["pattern"], body, re.IGNORECASE)
            if match:
                _add(fp["name"], fp["category"])

        # ── 4. JavaScript library fingerprinting ────────────────────
        for fp in JS_LIBRARY_FINGERPRINTS:
            match = re.search(fp["pattern"], body, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
                _add(fp["name"], fp["category"], version)

        # ── 5. Outdated technology findings ─────────────────────────
        for tech in detected:
            name_lower = tech["name"].lower()
            version = tech.get("version", "")

            # Flag known outdated jQuery versions
            if name_lower == "jquery" and version:
                try:
                    major = int(version.split(".")[0])
                    if major < 3:
                        await self._create_finding(
                            scan,
                            title=f"Outdated jQuery Version Detected ({version})",
                            description=f"The application uses jQuery {version} which contains known XSS and prototype pollution vulnerabilities.",
                            severity="medium",
                            owasp_category="A06:2021-Vulnerable and Outdated Components",
                            cwe_id="CWE-1104",
                            cvss_score=5.3,
                            affected_url=target_url,
                            remediation="Upgrade to jQuery 3.x or later.",
                            proof_of_concept=f"Detected jQuery version {version} in page source",
                            counts=counts,
                        )
                except (ValueError, IndexError):
                    pass

        results: dict[str, Any] = {"technologies": detected, "count": len(detected)}
        return results
