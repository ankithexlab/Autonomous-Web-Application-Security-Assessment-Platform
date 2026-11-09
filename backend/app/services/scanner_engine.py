"""
Real Passive Scanner Engine.

Executes safe, non-destructive passive HTTP assessment checks against target URLs:
  1. SSRF URL & Hostname validation (blocks private/loopback/cloud metadata IPs).
  2. Information Gathering (DNS, WHOIS, IP, Tech Detection, Directory Discovery).
  3. Primary HTTP Response Collection (status code, headers, response time).
  4. Security Headers Auditor (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
  5. Cookie Security Auditor (Set-Cookie: Secure, HttpOnly, SameSite attributes).
  6. HTTPS & Redirect Analysis (HTTP -> HTTPS enforcement, redirect chain length).
  7. Server Information Disclosure (Server, X-Powered-By header analysis).
  8. Passive /robots.txt & /sitemap.xml availability checks.
  9. OWASP Top 10 Checkers (A01 - A10).
  10. Security Analysis (CORS, Session Management).
  11. Vulnerability Detection (SQLi, XSS, CSRF, IDOR, Open Redirect, Command Injection, JWT, API Security, File Upload, Rate Limiting).
"""

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import json
import logging
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppException, BadRequestException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse
from app.core.ssrf import validate_target_url
from app.models.scan import Scan
from app.repositories.finding import FindingRepository
from app.repositories.scan import ScanRepository
from app.repositories.target import TargetRepository

# Import all scanner modules
from app.services.scanner.dns_lookup import DNSLookupModule
from app.services.scanner.whois_lookup import WHOISLookupModule
from app.services.scanner.ip_detection import IPDetectionModule
from app.services.scanner.tech_detection import TechDetectionModule
from app.services.scanner.directory_discovery import DirectoryDiscoveryModule
from app.services.scanner.crawler import SameOriginCrawlerModule
from app.services.scanner.cors_analyzer import CORSAnalyzerModule
from app.services.scanner.session_analyzer import SessionAnalyzerModule
from app.services.scanner.sqli_detector import SQLInjectionDetectorModule
from app.services.scanner.xss_detector import XSSDetectorModule
from app.services.scanner.csrf_detector import CSRFDetectorModule
from app.services.scanner.idor_detector import IDORDetectorModule
from app.services.scanner.open_redirect_detector import OpenRedirectDetectorModule
from app.services.scanner.command_injection_detector import CommandInjectionDetectorModule
from app.services.scanner.jwt_analyzer import JWTAnalyzerModule
from app.services.scanner.api_security import APISecurityModule
from app.services.scanner.file_upload_detector import FileUploadDetectorModule
from app.services.scanner.rate_limit_detector import RateLimitDetectorModule
from app.services.scanner.payload_test_runner import PayloadSecurityTestRunner
from app.services.scanner.input_validation import InputValidationModule

# Phase 5 — Passive Scanner Modules
from app.services.scanner.security_headers import SecurityHeadersModule
from app.services.scanner.cookie_security import CookieSecurityModule
from app.services.scanner.ssl_tls import SslTlsModule
from app.services.scanner.http_config import HttpConfigModule
from app.services.scanner.redirect_analysis import RedirectAnalysisModule
from app.services.scanner.https_redirect import HttpsRedirectModule
from app.services.scanner.robots_sitemap import RobotsSitemapModule
from app.services.scanner.endpoint_param_discovery import EndpointParamDiscoveryModule
from app.services.scanner.exposed_config_checker import ExposedConfigCheckerModule


logger = logging.getLogger("awsap.scanner.engine")

MODULE_ALIAS_MAP: dict[str, list[str]] = {
    "recon": ["dns_lookup", "whois_lookup", "ip_detection", "tech_detection", "directory_discovery", "robots_sitemap"],
    "crawler": ["crawler", "url_discovery", "endpoint_discovery"],
    "sqli": ["sqli_detector", "payload_test_runner"],
    "xss": ["xss_detector", "payload_test_runner"],
    "csrf": ["csrf_detector"],
    "auth": ["session_analyzer", "jwt_analyzer", "rate_limit"],
    "headers": ["security_headers", "cookie_audit", "cookie_security"],
    "ssl": ["ssl_tls", "http_config", "redirect_analysis", "https_redirect"],
    "api": ["api_security", "idor_detector", "open_redirect", "file_upload"],
    "ports": ["ip_detection"],
    "cmd_injection": ["cmd_injection"],
    "file_upload": ["file_upload"],
    "open_redirect": ["open_redirect"],
    "input_validation": ["input_validation"],
    # Phase 5 passive module presets
    "passive": [
        "security_headers",
        "ssl_tls",
        "cookie_security",
        "cookie_audit",
        "http_config",
        "redirect_analysis",
        "https_redirect",
        "tech_detection",
        "robots_sitemap",
        "url_discovery",
        "crawler",
        "endpoint_discovery",
        "exposed_config",
    ],
    # Phase 6 active vulnerability detection preset
    "active": [
        "sqli_detector",
        "xss_detector",
        "csrf_detector",
        "session_analyzer",
        "idor_detector",
        "api_security",
        "input_validation",
        "payload_test_runner",
    ],
}


class ScannerEngine:
    """Asynchronous passive security scanner engine with SSRF guardrails."""

    def __init__(
        self,
        session: AsyncSession,
        http_client: SafeHTTPClient | None = None,
    ) -> None:
        self._session = session
        self._scan_repo = ScanRepository(session)
        self._target_repo = TargetRepository(session)
        self._finding_repo = FindingRepository(session)
        self._http_client = http_client or SafeHTTPClient()

    async def _check_cancelled(self, scan_id: UUID) -> bool:
        refreshed = await self._scan_repo.get_by_id(scan_id)
        return bool(refreshed and refreshed.status == "CANCELLED")

    def _get_active_modules(self, scan: Scan) -> set[str] | None:
        """Resolve active modules from scan configuration, expanding preset/alias keys."""
        if not scan.config_json:
            return None
        try:
            cfg = json.loads(scan.config_json)
            if isinstance(cfg, dict) and "modules" in cfg and isinstance(cfg["modules"], list) and cfg["modules"]:
                resolved: set[str] = set()
                for m in cfg["modules"]:
                    resolved.add(m)
                    if m in MODULE_ALIAS_MAP:
                        resolved.update(MODULE_ALIAS_MAP[m])
                return resolved
        except Exception:
            pass
        return None

    def _is_module_enabled(self, module_id: str, active_modules: set[str] | None) -> bool:
        if active_modules is None or len(active_modules) == 0:
            return True
        return module_id in active_modules

    async def run_scan(self, scan_id: UUID) -> Scan:
        scan = await self._scan_repo.get_by_id(scan_id)
        if not scan:
            raise BadRequestException(f"Scan {scan_id} not found.")

        if scan.status == "CANCELLED":
            logger.info("Scan cancelled before launch: scan_id=%s", scan_id)
            return scan

        target = await self._target_repo.get_by_id(scan.target_id)
        if not target:
            raise BadRequestException(f"Target with ID {scan.target_id} not found for scan {scan.id}.")
        target_url = target.url
        logger.info("Scan started: scan_id=%s target_url=%s", scan.id, target_url)

        # Update status to RUNNING
        await self._scan_repo.update_status(scan, "RUNNING", progress=5)
        await self._session.commit()

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        module_results: dict[str, dict] = {}
        active_modules = self._get_active_modules(scan)

        try:
            # ── Stage 1 (5%): URL & SSRF Validation ──────────────────
            scan.progress = 5
            await self._session.commit()
            if await self._check_cancelled(scan.id):
                return scan
            validated_url = validate_target_url(target_url)
            module_results["ssrf_validation"] = {
                "status": "completed",
                "module_name": "SSRF & Hostname Guardrails",
                "target_url": validated_url,
            }

            # Explicit active scan confirmation and scope tracking
            is_active_confirmed = False
            if scan.config_json:
                try:
                    cfg = json.loads(scan.config_json)
                    if isinstance(cfg, dict):
                        is_active_confirmed = bool(cfg.get("active_confirmed") or cfg.get("active_scan_confirmed"))
                except Exception:
                    pass

            module_results["active_scan_authorization"] = {
                "status": "completed" if is_active_confirmed else "skipped",
                "module_name": "Active Scan Scope & Authorization",
                "active_confirmed": is_active_confirmed,
                "scan_type": scan.scan_type,
                "target_url": validated_url,
                "scope_enforced": True,
            }
            scan.modules_json = json.dumps(module_results, default=str)
            await self._session.commit()

            # ── Stage 2 (15%): Information Gathering ─────────────────
            scan.progress = 15
            await self._session.commit()
            if await self._check_cancelled(scan.id):
                return scan
            module_results.update(
                await self._run_info_gathering(scan, validated_url, severity_counts, active_modules)
            )
            scan.modules_json = json.dumps(module_results, default=str)
            await self._session.commit()

            # ── Stage 3 (30%): Primary HTTP Response Collection ──────
            scan.progress = 30
            await self._session.commit()
            if await self._check_cancelled(scan.id):
                return scan

            main_resp: SafeHTTPResponse | None = None
            try:
                main_resp = await self._http_client.get(validated_url)
                module_results["http_reachability"] = {
                    "status": "completed",
                    "module_name": "Primary HTTP Collection",
                    "status_code": main_resp.status_code,
                    "elapsed_seconds": round(main_resp.elapsed_seconds, 3),
                }
            except AppException:
                raise
            except Exception as e:
                module_results["http_reachability"] = {
                    "status": "error",
                    "module_name": "Primary HTTP Collection",
                    "error": str(e),
                }
                scan.modules_json = json.dumps(module_results, default=str)
                await self._session.commit()
                raise BadRequestException(f"Target reachability check failed for '{validated_url}': {e}")
            scan.modules_json = json.dumps(module_results, default=str)
            await self._session.commit()

            # ── Stage 4 (45%): Security Headers & Cookie Analysis ────
            scan.progress = 45
            await self._session.commit()
            if await self._check_cancelled(scan.id):
                return scan

            if main_resp:
                # Phase 5 SecurityHeadersModule — replaces inline _audit_security_headers
                if self._is_module_enabled("security_headers", active_modules):
                    try:
                        sh_module = SecurityHeadersModule(self._finding_repo)
                        sh_result = await sh_module.run(scan, validated_url, main_resp, self._http_client, severity_counts)
                        module_results["security_headers"] = {
                            "status": sh_result.get("status", "completed"),
                            "module_name": "Security Headers Analysis",
                            **{k: v for k, v in sh_result.items() if k != "status"},
                        }
                    except Exception as e:
                        logger.warning("SecurityHeadersModule error: %s", e)
                        module_results["security_headers"] = {
                            "status": "error",
                            "module_name": "Security Headers Analysis",
                            "error": str(e),
                        }
                else:
                    module_results["security_headers"] = {
                        "status": "skipped",
                        "module_name": "Security Headers Analysis",
                        "reason": "Module not selected for this scan",
                    }

                # Phase 5 CookieSecurityModule — replaces inline _audit_cookies
                if self._is_module_enabled("cookie_security", active_modules) or self._is_module_enabled("cookie_audit", active_modules) or self._is_module_enabled("session_analyzer", active_modules):
                    try:
                        ck_module = CookieSecurityModule(self._finding_repo)
                        ck_result = await ck_module.run(scan, validated_url, main_resp, self._http_client, severity_counts)
                        module_results["cookie_security"] = {
                            "status": ck_result.get("status", "completed"),
                            "module_name": "Cookie Security Attributes",
                            **{k: v for k, v in ck_result.items() if k != "status"},
                        }
                        # Keep legacy key for backwards compatibility
                        module_results["cookie_audit"] = module_results["cookie_security"]
                    except Exception as e:
                        logger.warning("CookieSecurityModule error: %s", e)
                        module_results["cookie_security"] = {
                            "status": "error",
                            "module_name": "Cookie Security Attributes",
                            "error": str(e),
                        }
                        module_results["cookie_audit"] = module_results["cookie_security"]
                else:
                    module_results["cookie_security"] = {
                        "status": "skipped",
                        "module_name": "Cookie Security Attributes",
                        "reason": "Module not selected for this scan",
                    }
                    module_results["cookie_audit"] = module_results["cookie_security"]

                scan.modules_json = json.dumps(module_results, default=str)
                await self._session.commit()

            # ── Stage 5 (55%): HTTPS, SSL/TLS & Redirect Analysis ────
            scan.progress = 55
            await self._session.commit()
            if await self._check_cancelled(scan.id):
                return scan

            if main_resp:
                # Module 2: SSL/TLS Observations
                if self._is_module_enabled("ssl_tls", active_modules):
                    try:
                        ssl_mod = SslTlsModule(self._finding_repo)
                        ssl_res = await ssl_mod.run(scan, validated_url, main_resp, self._http_client, severity_counts)
                        module_results["ssl_tls"] = {
                            "status": ssl_res.get("status", "completed"),
                            "module_name": "SSL/TLS Observations",
                            **{k: v for k, v in ssl_res.items() if k != "status"},
                        }
                    except Exception as e:
                        logger.warning("SslTlsModule error: %s", e)
                        module_results["ssl_tls"] = {
                            "status": "error",
                            "module_name": "SSL/TLS Observations",
                            "error": str(e),
                        }
                else:
                    module_results["ssl_tls"] = {
                        "status": "skipped",
                        "module_name": "SSL/TLS Observations",
                        "reason": "Module not selected for this scan",
                    }

                # Module 4: HTTP/HTTPS Configuration
                if self._is_module_enabled("http_config", active_modules) or self._is_module_enabled("https_redirect", active_modules) or self._is_module_enabled("ssl_tls", active_modules):
                    try:
                        http_cfg_mod = HttpConfigModule(self._finding_repo)
                        http_cfg_res = await http_cfg_mod.run(scan, validated_url, main_resp, self._http_client, severity_counts)
                        module_results["http_config"] = {
                            "status": http_cfg_res.get("status", "completed"),
                            "module_name": "HTTP/HTTPS Configuration",
                            **{k: v for k, v in http_cfg_res.items() if k != "status"},
                        }
                    except Exception as e:
                        logger.warning("HttpConfigModule error: %s", e)
                        module_results["http_config"] = {
                            "status": "error",
                            "module_name": "HTTP/HTTPS Configuration",
                            "error": str(e),
                        }
                else:
                    module_results["http_config"] = {
                        "status": "skipped",
                        "module_name": "HTTP/HTTPS Configuration",
                        "reason": "Module not selected for this scan",
                    }

                # Module 5: Redirect Analysis
                if self._is_module_enabled("redirect_analysis", active_modules) or self._is_module_enabled("https_redirect", active_modules):
                    try:
                        redir_mod = RedirectAnalysisModule(self._finding_repo)
                        redir_res = await redir_mod.run(scan, validated_url, main_resp, self._http_client, severity_counts)
                        module_results["redirect_analysis"] = {
                            "status": redir_res.get("status", "completed"),
                            "module_name": "Redirect Analysis",
                            **{k: v for k, v in redir_res.items() if k != "status"},
                        }
                    except Exception as e:
                        logger.warning("RedirectAnalysisModule error: %s", e)
                        module_results["redirect_analysis"] = {
                            "status": "error",
                            "module_name": "Redirect Analysis",
                            "error": str(e),
                        }
                else:
                    module_results["redirect_analysis"] = {
                        "status": "skipped",
                        "module_name": "Redirect Analysis",
                        "reason": "Module not selected for this scan",
                    }

                # Composite https_redirect entry for backwards compatibility
                module_results["https_redirect"] = {
                    "status": "completed",
                    "module_name": "HTTP/HTTPS Configuration & Redirect Analysis",
                    "enforces_https": module_results.get("http_config", {}).get("enforces_https", False),
                    "hops_count": module_results.get("redirect_analysis", {}).get("hops_count", 0),
                }

                scan.modules_json = json.dumps(module_results, default=str)
                await self._session.commit()

            # ── Stage 6 (65%): Surface Mapping, Sensitive Configs & Info Disclosure ────
            scan.progress = 65
            await self._session.commit()
            if await self._check_cancelled(scan.id):
                return scan

            if main_resp:
                # Module 7: robots.txt & sitemap.xml Analysis
                if self._is_module_enabled("robots_sitemap", active_modules) or self._is_module_enabled("directory_discovery", active_modules):
                    try:
                        robots_mod = RobotsSitemapModule(self._finding_repo)
                        robots_res = await robots_mod.run(scan, validated_url, main_resp, self._http_client, severity_counts)
                        module_results["robots_sitemap"] = {
                            "status": robots_res.get("status", "completed"),
                            "module_name": "robots.txt & sitemap.xml Analysis",
                            **{k: v for k, v in robots_res.items() if k != "status"},
                        }
                    except Exception as e:
                        logger.warning("RobotsSitemapModule error: %s", e)
                        module_results["robots_sitemap"] = {
                            "status": "error",
                            "module_name": "robots.txt & sitemap.xml Analysis",
                            "error": str(e),
                        }
                else:
                    module_results["robots_sitemap"] = {
                        "status": "skipped",
                        "module_name": "robots.txt & sitemap.xml Analysis",
                        "reason": "Module not selected for this scan",
                    }

                # Module 9: Endpoint & Parameter Discovery (derived from crawler and responses)
                if self._is_module_enabled("endpoint_discovery", active_modules) or self._is_module_enabled("url_discovery", active_modules) or self._is_module_enabled("crawler", active_modules):
                    try:
                        ep_mod = EndpointParamDiscoveryModule(self._finding_repo)
                        ep_res = await ep_mod.run(scan, validated_url, main_resp, self._http_client, severity_counts)
                        module_results["endpoint_discovery"] = {
                            "status": ep_res.get("status", "completed"),
                            "module_name": "Endpoint & Parameter Discovery",
                            **{k: v for k, v in ep_res.items() if k != "status"},
                        }
                    except Exception as e:
                        logger.warning("EndpointParamDiscoveryModule error: %s", e)
                        module_results["endpoint_discovery"] = {
                            "status": "error",
                            "module_name": "Endpoint & Parameter Discovery",
                            "error": str(e),
                        }
                else:
                    module_results["endpoint_discovery"] = {
                        "status": "skipped",
                        "module_name": "Endpoint & Parameter Discovery",
                        "reason": "Module not selected for this scan",
                    }

                # Module 10: Publicly Exposed Configuration Checks
                if self._is_module_enabled("exposed_config", active_modules) or self._is_module_enabled("directory_discovery", active_modules):
                    try:
                        exp_mod = ExposedConfigCheckerModule(self._finding_repo)
                        exp_res = await exp_mod.run(scan, validated_url, main_resp, self._http_client, severity_counts)
                        module_results["exposed_config"] = {
                            "status": exp_res.get("status", "completed"),
                            "module_name": "Publicly Exposed Configuration Checks",
                            **{k: v for k, v in exp_res.items() if k != "status"},
                        }
                    except Exception as e:
                        logger.warning("ExposedConfigCheckerModule error: %s", e)
                        module_results["exposed_config"] = {
                            "status": "error",
                            "module_name": "Publicly Exposed Configuration Checks",
                            "error": str(e),
                        }
                else:
                    module_results["exposed_config"] = {
                        "status": "skipped",
                        "module_name": "Publicly Exposed Configuration Checks",
                        "reason": "Module not selected for this scan",
                    }

                if self._is_module_enabled("tech_detection", active_modules):
                    await self._audit_info_disclosure(scan, main_resp, severity_counts)

                scan.modules_json = json.dumps(module_results, default=str)
                await self._session.commit()

            # ── Stage 7 (75%): OWASP Top 10 Checks ──────────────────
            scan.progress = 75
            await self._session.commit()
            if await self._check_cancelled(scan.id):
                return scan

            if main_resp:
                from app.services.owasp.owasp_engine import OWASPEngine
                owasp_engine = OWASPEngine(self._finding_repo)
                await owasp_engine.execute_owasp_checks(scan, main_resp, severity_counts)
                module_results["owasp_top_10"] = {
                    "status": "completed",
                    "module_name": "OWASP Top 10 Compliance Checkers",
                }
                scan.modules_json = json.dumps(module_results, default=str)
                await self._session.commit()

            # ── Stage 8 (85%): Security Analysis Modules ─────────────
            scan.progress = 85
            await self._session.commit()
            if await self._check_cancelled(scan.id):
                return scan

            if main_resp:
                module_results.update(
                    await self._run_security_analysis(scan, validated_url, main_resp, severity_counts, active_modules)
                )
                scan.modules_json = json.dumps(module_results, default=str)
                await self._session.commit()

            # ── Stage 9 (95%): Vulnerability Detection Modules ───────
            scan.progress = 95
            await self._session.commit()
            if await self._check_cancelled(scan.id):
                return scan

            if main_resp:
                module_results.update(
                    await self._run_vulnerability_detection(scan, validated_url, main_resp, severity_counts, active_modules)
                )
                scan.modules_json = json.dumps(module_results, default=str)
                await self._session.commit()

            # ── Stage 10 (100%): Summary Compilation & Completion ────
            scan.progress = 100

            # Verify that at least one module completed successfully or generated findings
            completed_count = sum(1 for r in module_results.values() if isinstance(r, dict) and r.get("status") == "completed")
            error_count = sum(1 for r in module_results.values() if isinstance(r, dict) and r.get("status") == "error")

            if completed_count == 0 and error_count > 0:
                scan.status = "FAILED"
                logger.warning("Scan %s marked as FAILED: all attempted modules produced fatal errors", scan.id)
            else:
                scan.status = "COMPLETED"

            scan.completed_at = datetime.now(timezone.utc)
            scan.critical_count = severity_counts["critical"]
            scan.high_count = severity_counts["high"]
            scan.medium_count = severity_counts["medium"]
            scan.low_count = severity_counts["low"]
            scan.info_count = severity_counts["info"]
            scan.findings_count = sum(severity_counts.values())

            # Store module results as JSON
            try:
                scan.modules_json = json.dumps(module_results, default=str)
            except Exception:
                scan.modules_json = "{}"

            await self._session.commit()
            logger.info(
                "Scan finished: scan_id=%s status=%s total_findings=%d (critical=%d, high=%d, medium=%d, low=%d, info=%d)",
                scan.id,
                scan.status,
                scan.findings_count,
                scan.critical_count,
                scan.high_count,
                scan.medium_count,
                scan.low_count,
                scan.info_count,
            )
            return scan

        except asyncio.CancelledError:
            scan.status = "CANCELLED"
            scan.completed_at = datetime.now(timezone.utc)
            try:
                scan.modules_json = json.dumps(module_results, default=str)
            except Exception:
                pass
            with suppress(Exception):
                await self._session.commit()
            logger.info("Scan cancelled during execution: scan_id=%s", scan.id)
            raise
        except Exception as scan_err:
            # Handle failure state cleanly, preserving CANCELLED status if already set
            if scan.status != "CANCELLED":
                scan.status = "FAILED"
                scan.completed_at = datetime.now(timezone.utc)
                try:
                    scan.modules_json = json.dumps(module_results, default=str)
                except Exception:
                    pass
                with suppress(Exception):
                    await self._session.commit()
            logger.error("Scan execution failed: scan_id=%s error=%s", scan.id, type(scan_err).__name__)
            raise scan_err

    # ── Information Gathering Modules ────────────────────────────

    async def _run_info_gathering(
        self,
        scan: Scan,
        target_url: str,
        counts: dict[str, int],
        active_modules: set[str] | None = None,
    ) -> dict[str, dict]:
        results: dict[str, dict] = {}
        modules = [
            DNSLookupModule(self._finding_repo),
            WHOISLookupModule(self._finding_repo),
            IPDetectionModule(self._finding_repo),
            TechDetectionModule(self._finding_repo),
            DirectoryDiscoveryModule(self._finding_repo),
            SameOriginCrawlerModule(self._finding_repo),
        ]

        for module in modules:
            if not self._is_module_enabled(module.module_id, active_modules):
                results[module.module_id] = {
                    "status": "skipped",
                    "reason": "Module not selected for this scan",
                    "module_name": getattr(module, "module_name", module.module_id),
                }
                continue

            try:
                result = await module.run(
                    scan, target_url, None, self._http_client, counts
                )
                if isinstance(result, dict):
                    if "status" not in result:
                        result["status"] = "completed"
                    result["module_name"] = getattr(module, "module_name", module.module_id)
                results[module.module_id] = result
            except Exception as e:
                logger.warning("Module %s execution error: %s", module.module_id, e, exc_info=True)
                results[module.module_id] = {
                    "status": "error",
                    "error": str(e),
                    "module_name": getattr(module, "module_name", module.module_id),
                }

        return results

    # ── Security Analysis Modules ────────────────────────────────

    async def _run_security_analysis(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
        active_modules: set[str] | None = None,
    ) -> dict[str, dict]:
        results: dict[str, dict] = {}
        modules = [
            CORSAnalyzerModule(self._finding_repo),
            SessionAnalyzerModule(self._finding_repo),
        ]

        for module in modules:
            if not self._is_module_enabled(module.module_id, active_modules):
                results[module.module_id] = {
                    "status": "skipped",
                    "reason": "Module not selected for this scan",
                    "module_name": getattr(module, "module_name", module.module_id),
                }
                continue

            try:
                result = await module.run(
                    scan, target_url, main_resp, self._http_client, counts
                )
                if isinstance(result, dict):
                    if "status" not in result:
                        result["status"] = "completed"
                    result["module_name"] = getattr(module, "module_name", module.module_id)
                results[module.module_id] = result
            except Exception as e:
                logger.warning("Module %s execution error: %s", module.module_id, e, exc_info=True)
                results[module.module_id] = {
                    "status": "error",
                    "error": str(e),
                    "module_name": getattr(module, "module_name", module.module_id),
                }

        return results

    # ── Vulnerability Detection Modules ──────────────────────────

    async def _run_vulnerability_detection(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse,
        counts: dict[str, int],
        active_modules: set[str] | None = None,
    ) -> dict[str, dict]:
        results: dict[str, dict] = {}
        modules = [
            SQLInjectionDetectorModule(self._finding_repo),
            XSSDetectorModule(self._finding_repo),
            CSRFDetectorModule(self._finding_repo),
            IDORDetectorModule(self._finding_repo),
            OpenRedirectDetectorModule(self._finding_repo),
            CommandInjectionDetectorModule(self._finding_repo),
            JWTAnalyzerModule(self._finding_repo),
            APISecurityModule(self._finding_repo),
            FileUploadDetectorModule(self._finding_repo),
            RateLimitDetectorModule(self._finding_repo),
            InputValidationModule(self._finding_repo),
            PayloadSecurityTestRunner(self._finding_repo, self._session),
        ]

        for module in modules:
            if not self._is_module_enabled(module.module_id, active_modules):
                results[module.module_id] = {
                    "status": "skipped",
                    "reason": "Module not selected for this scan",
                    "module_name": getattr(module, "module_name", module.module_id),
                }
                continue

            try:
                result = await module.run(
                    scan, target_url, main_resp, self._http_client, counts
                )
                if isinstance(result, dict):
                    if "status" not in result:
                        result["status"] = "completed"
                    result["module_name"] = getattr(module, "module_name", module.module_id)
                results[module.module_id] = result
            except Exception as e:
                logger.warning("Module %s execution error: %s", module.module_id, e, exc_info=True)
                results[module.module_id] = {
                    "status": "error",
                    "error": str(e),
                    "module_name": getattr(module, "module_name", module.module_id),
                }

        return results

    # ── Original Audit Check Implementations ─────────────────────

    async def _audit_security_headers(
        self, scan: Scan, resp: SafeHTTPResponse, counts: dict[str, int]
    ) -> None:
        headers = resp.headers

        # 1. Content-Security-Policy
        if "content-security-policy" not in headers:
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Missing Content-Security-Policy Header",
                description="The application does not set a Content-Security-Policy (CSP) response header, increasing susceptibility to Cross-Site Scripting (XSS) and data injection attacks.",
                severity="low",
                category="Security Headers",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-693",
                cvss_score=3.8,
                affected_url=resp.url,
                remediation="Configure a restrictive Content-Security-Policy header (e.g. default-src 'self').",
                proof_of_concept=f"HTTP response headers for {resp.url} do not include Content-Security-Policy",
            )
            if f is not None:
                counts["low"] += 1

        # 2. Strict-Transport-Security (HSTS)
        if resp.url.startswith("https://") and "strict-transport-security" not in headers:
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                description="The HTTPS web application does not enforce HSTS, leaving users vulnerable to SSL stripping and man-in-the-middle downgrade attacks.",
                severity="medium",
                category="Security Headers",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-523",
                cvss_score=5.3,
                affected_url=resp.url,
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to HTTPS response headers.",
                proof_of_concept=f"HTTP response headers for {resp.url} do not include Strict-Transport-Security",
            )
            if f is not None:
                counts["medium"] += 1

        # 3. X-Frame-Options
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Missing Anti-Clickjacking Protection (X-Frame-Options)",
                description="The application does not declare an X-Frame-Options header, allowing framing by external origins (Clickjacking risk).",
                severity="low",
                category="Security Headers",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-1021",
                cvss_score=3.4,
                affected_url=resp.url,
                remediation="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' on all HTML responses.",
                proof_of_concept=f"HTTP response headers for {resp.url} do not include X-Frame-Options",
            )
            if f is not None:
                counts["low"] += 1

        # 4. X-Content-Type-Options
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Missing X-Content-Type-Options Header",
                description="The response header X-Content-Type-Options is missing or not set to 'nosniff', permitting MIME-sniffing vulnerabilities.",
                severity="info",
                category="Security Headers",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-79",
                cvss_score=2.6,
                affected_url=resp.url,
                remediation="Set 'X-Content-Type-Options: nosniff' on all response headers.",
                proof_of_concept=f"X-Content-Type-Options header value: '{headers.get('x-content-type-options', 'NONE')}'",
            )
            if f is not None:
                counts["info"] += 1

    async def _audit_cookies(
        self, scan: Scan, resp: SafeHTTPResponse, counts: dict[str, int]
    ) -> None:
        # Inspect Set-Cookie header if present
        set_cookie = resp.headers.get("set-cookie", "")
        if not set_cookie:
            return

        cookie_lower = set_cookie.lower()
        missing_flags = []

        if resp.url.startswith("https://") and "secure" not in cookie_lower:
            missing_flags.append("Secure")
        if "httponly" not in cookie_lower:
            missing_flags.append("HttpOnly")
        if "samesite" not in cookie_lower:
            missing_flags.append("SameSite")

        if missing_flags:
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Insecure Cookie Attributes Detected",
                description=f"Session cookies set by the server are missing critical security attributes: {', '.join(missing_flags)}.",
                severity="medium",
                category="Cookie Security",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-614",
                cvss_score=4.8,
                affected_url=resp.url,
                remediation="Ensure all cookies set by the application declare Secure, HttpOnly, and SameSite=Lax (or Strict) attributes.",
                proof_of_concept=f"Set-Cookie header: '{set_cookie}'",
            )
            if f is not None:
                counts["medium"] += 1

    async def _audit_https_and_redirects(
        self, scan: Scan, original_url: str, resp: SafeHTTPResponse, counts: dict[str, int]
    ) -> None:
        if original_url.startswith("http://") and not resp.url.startswith("https://"):
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Unencrypted HTTP Service (No HTTPS Enforcement)",
                description="The target target communicates over unencrypted HTTP and does not redirect users to HTTPS.",
                severity="high",
                category="Encryption",
                owasp_category="A02:2021-Cryptographic Failures",
                cwe_id="CWE-319",
                cvss_score=7.5,
                affected_url=original_url,
                remediation="Configure the web server to automatically redirect HTTP requests to HTTPS.",
                proof_of_concept=f"GET {original_url} resolved to non-HTTPS URL {resp.url}",
            )
            if f is not None:
                counts["high"] += 1

        if len(resp.redirect_chain) > 3:
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Excessive HTTP Redirect Chain",
                description=f"The target URL triggered an unusually long HTTP redirect chain ({len(resp.redirect_chain)} hops).",
                severity="info",
                category="Redirect Analysis",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-601",
                cvss_score=2.0,
                affected_url=original_url,
                remediation="Optimize server routing to avoid multi-step HTTP redirects.",
                proof_of_concept=f"Redirect chain: {' -> '.join(resp.redirect_chain)}",
            )
            if f is not None:
                counts["info"] += 1

    async def _audit_info_disclosure(
        self, scan: Scan, resp: SafeHTTPResponse, counts: dict[str, int]
    ) -> None:
        headers = resp.headers
        disclosed = []

        if "server" in headers:
            disclosed.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            disclosed.append(f"X-Powered-By: {headers['x-powered-by']}")

        if disclosed:
            f = await self._finding_repo.create(
                scan_id=scan.id,
                target_id=scan.target_id,
                project_id=scan.project_id,
                user_id=scan.user_id,
                title="Server & Technology Information Disclosure",
                description="HTTP response headers expose underlying server software and technology stack versions.",
                severity="info",
                category="Information Disclosure",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-200",
                cvss_score=2.1,
                affected_url=resp.url,
                remediation="Suppress Server and X-Powered-By banners in web server configuration.",
                proof_of_concept="; ".join(disclosed),
            )
            if f is not None:
                counts["info"] += 1

    async def _check_robots_and_sitemap(
        self, scan: Scan, base_url: str, counts: dict[str, int]
    ) -> None:
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Passive /robots.txt check
        try:
            robots_url = f"{origin}/robots.txt"
            r_resp = await self._http_client.get(robots_url)
            if r_resp.status_code == 200 and "Disallow" in r_resp.text:
                f = await self._finding_repo.create(
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    project_id=scan.project_id,
                    user_id=scan.user_id,
                    title="Exposed Disallow Directives in robots.txt",
                    description="The target exposes a public /robots.txt file containing Disallow directives that disclose sensitive administrative or hidden endpoint locations.",
                    severity="info",
                    category="Information Disclosure",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-200",
                    cvss_score=2.0,
                    affected_url=robots_url,
                    remediation="Review robots.txt directives to ensure sensitive administrative URLs are not disclosed publicly.",
                    proof_of_concept=f"GET {robots_url} returned status 200 with Disallow directives",
                )
                if f is not None:
                    counts["info"] += 1
        except Exception:
            pass

        # 2. Passive /sitemap.xml check
        try:
            sitemap_url = f"{origin}/sitemap.xml"
            s_resp = await self._http_client.get(sitemap_url)
            if s_resp.status_code == 200:
                f = await self._finding_repo.create(
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    project_id=scan.project_id,
                    user_id=scan.user_id,
                    title="Public XML Sitemap Available",
                    description="The target publishes an XML sitemap at /sitemap.xml disclosing application structure and route endpoints.",
                    severity="info",
                    category="Information Disclosure",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-200",
                    cvss_score=1.5,
                    affected_url=sitemap_url,
                    remediation="Ensure only public pages are declared within sitemap.xml.",
                    proof_of_concept=f"GET {sitemap_url} returned status 200",
                )
                if f is not None:
                    counts["info"] += 1
        except Exception:
            pass
