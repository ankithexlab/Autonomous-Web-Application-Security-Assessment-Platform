"""
Same-Origin URL Discovery & Crawler Module.

Performs safely bounded, same-origin web crawling up to:
  - Max depth: 2
  - Max discovered URLs: 25
  - Strictly same-origin (protocol, host, port)
  - SSRF re-validation on every candidate URL
  - Explicit exclusion of dangerous/state-changing routes (logout, delete, pay, upload, etc.)
  - URL normalization and deduplication
"""

import asyncio
import logging
import time
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from app.core.exceptions import AppException
from app.core.http_client import SafeHTTPClient, SafeHTTPResponse, validate_target_url
from app.models.scan import Scan
from app.repositories.finding import FindingRepository
from app.services.scanner.base_module import BaseScannerModule

logger = logging.getLogger(__name__)


# Disallowed route tokens (state-changing or sensitive actions)
DISALLOWED_PATH_TOKENS = {
    "logout",
    "log-out",
    "signout",
    "sign-out",
    "delete",
    "destroy",
    "remove",
    "pay",
    "payment",
    "checkout",
    "billing",
    "upload",
    "reset-password",
    "password-reset",
    "terminate",
    "deactivate",
    "cancel",
    "unsubscribe",
}

# Static file extensions to skip during crawling
IGNORED_STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".wav", ".ogg",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dmg", ".pkg", ".deb", ".rpm",
}


class _HrefExtractor(HTMLParser):
    """Simple, secure HTML parser to extract link candidates from HTML responses."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attrs_dict = {k.lower(): v for k, v in attrs if v is not None}

        if tag_lower == "a" and "href" in attrs_dict:
            self.links.append(attrs_dict["href"])
        elif tag_lower == "form" and "action" in attrs_dict:
            self.links.append(attrs_dict["action"])
        elif tag_lower == "link" and "href" in attrs_dict:
            rel = attrs_dict.get("rel", "").lower()
            if rel in ("canonical", "alternate", "next", "prev"):
                self.links.append(attrs_dict["href"])


class SameOriginCrawlerModule(BaseScannerModule):
    """
    Crawls target web application to discover same-origin endpoints.
    Safely restricted by depth, maximum URL count, SSRF validation, and action route exclusion.
    """

    module_id = "url_discovery"
    module_name = "Same-Origin URL Discovery & Crawler"
    category = "info_gathering"

    MAX_DEPTH: int = 2
    MAX_URLS: int = 25
    REQUEST_TIMEOUT: float = 4.0
    MAX_CRAWL_DURATION_SECONDS: float = 15.0

    def __init__(self, finding_repo: FindingRepository) -> None:
        super().__init__(finding_repo)

    @staticmethod
    def normalize_url(raw_url: str) -> str:
        """Normalizes URL by stripping fragments and trailing slash (except root)."""
        split = urlsplit(raw_url)
        path = split.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        return urlunsplit((split.scheme.lower(), split.netloc.lower(), path, split.query, ""))

    @classmethod
    def is_state_changing_or_sensitive(cls, url: str) -> bool:
        """Determines if a URL path or query contains sensitive or state-changing action keywords."""
        split = urlsplit(url)
        full_text = f"{split.path.lower()}?{split.query.lower()}"
        for kw in DISALLOWED_PATH_TOKENS:
            if kw in full_text:
                return True
        tokens = set("".join(c if c.isalnum() else " " for c in full_text).split())
        return bool(tokens & DISALLOWED_PATH_TOKENS)


    @classmethod
    def is_ignored_asset(cls, path: str) -> bool:
        """Determines if the path points to a static media/asset file."""
        lower_path = path.lower()
        return any(lower_path.endswith(ext) for ext in IGNORED_STATIC_EXTENSIONS)

    async def run(
        self,
        scan: Scan,
        target_url: str,
        main_resp: SafeHTTPResponse | None,
        http_client: SafeHTTPClient,
        counts: dict[str, int],
    ) -> dict[str, Any]:
        """
        Executes safe same-origin breadth-first search (BFS) crawling.
        """
        start_time = time.monotonic()
        target_norm = self.normalize_url(target_url)
        target_split = urlsplit(target_norm)
        target_origin = (target_split.scheme, target_split.netloc)

        visited: set[str] = set()
        discovered_urls: list[str] = []
        queue: list[tuple[str, int]] = [(target_norm, 0)]
        max_depth_reached = 0

        # If primary response is available for root, we can use its HTML without an extra request
        root_resp_used = False

        while queue and len(discovered_urls) < self.MAX_URLS:
            # Check maximum crawl duration
            if (time.monotonic() - start_time) > self.MAX_CRAWL_DURATION_SECONDS:
                logger.info(f"Crawl time budget exceeded for scan {scan.id}; stopping crawl.")
                break

            current_url, depth = queue.pop(0)

            if current_url in visited:
                continue
            visited.add(current_url)

            if depth > max_depth_reached:
                max_depth_reached = depth

            # If this is not the root seed URL, track it as a discovered URL
            if current_url != target_norm:
                discovered_urls.append(current_url)
                if len(discovered_urls) >= self.MAX_URLS:
                    break

            # If depth limit reached, do not crawl children
            if depth >= self.MAX_DEPTH:
                continue

            # Fetch page content
            html_content: str | None = None
            if current_url == target_norm and main_resp and main_resp.text and not root_resp_used:
                main_split = urlsplit(main_resp.url)
                if (main_split.scheme.lower(), main_split.netloc.lower()) == target_origin:
                    html_content = main_resp.text
                root_resp_used = True
            else:
                try:
                    resp = await http_client.get(current_url, timeout=self.REQUEST_TIMEOUT)
                    # Enforce origin boundary: verify final response URL remains within validated target origin
                    resp_split = urlsplit(resp.url)
                    if (resp_split.scheme.lower(), resp_split.netloc.lower()) != target_origin:
                        logger.info(
                            "Response URL %s redirected outside target origin %s; skipping HTML parsing.",
                            resp.url,
                            target_origin,
                        )
                        continue

                    content_type = resp.headers.get("content-type", "").lower()
                    # Only parse HTML responses
                    if "text/html" in content_type or "<html" in (resp.text or "").lower():
                        html_content = resp.text
                except Exception as exc:
                    logger.debug("Failed to fetch %s during crawl: %s", current_url, exc)
                    continue

            if not html_content:
                continue

            # Parse extracted links
            parser = _HrefExtractor()
            try:
                parser.feed(html_content)
            except Exception:
                continue

            for raw_href in parser.links:
                if not raw_href or raw_href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                    continue

                # Resolve relative URL
                absolute_url = urljoin(current_url, raw_href)
                normalized_candidate = self.normalize_url(absolute_url)
                candidate_split = urlsplit(normalized_candidate)

                # 1. Scheme check (http / https only)
                if candidate_split.scheme not in ("http", "https"):
                    continue

                # 2. Origin check (strictly identical scheme and netloc)
                if (candidate_split.scheme, candidate_split.netloc) != target_origin:
                    continue

                # 3. Static asset check
                if self.is_ignored_asset(candidate_split.path):
                    continue

                # 4. State-changing / sensitive route check
                if self.is_state_changing_or_sensitive(normalized_candidate):
                    logger.debug(f"Skipping dangerous route candidate: {normalized_candidate}")
                    continue

                # 5. SSRF validation check
                try:
                    validate_target_url(normalized_candidate)
                except (AppException, Exception):
                    logger.warning(f"Candidate URL {normalized_candidate} failed SSRF validation; skipping.")
                    continue

                # 6. Deduplication and enqueue
                if normalized_candidate not in visited and all(u != normalized_candidate for u, _ in queue):
                    queue.append((normalized_candidate, depth + 1))

        # Record informational finding if endpoints were discovered
        if discovered_urls:
            url_list_str = "\n".join(f"- {u}" for u in discovered_urls[:15])
            if len(discovered_urls) > 15:
                url_list_str += f"\n- ... and {len(discovered_urls) - 15} more"

            await self._create_finding(
                scan,
                title=f"Discovered {len(discovered_urls)} Same-Origin Endpoints via Crawl",
                description=(
                    f"Automated crawler discovered {len(discovered_urls)} same-origin endpoints "
                    f"within maximum depth {self.MAX_DEPTH}. These endpoints represent the application attack surface."
                ),
                severity="info",
                category="info_gathering",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-200",
                cvss_score=0.0,
                affected_url=target_norm,
                remediation="Ensure endpoints are properly protected with authentication and authorization checks.",
                proof_of_concept=f"Discovered URLs:\n{url_list_str}",
                counts=counts,
            )

        return {
            "target_url": target_norm,
            "total_discovered": len(discovered_urls),
            "max_depth_reached": max_depth_reached,
            "discovered_urls": discovered_urls,
            "limits": {
                "max_depth": self.MAX_DEPTH,
                "max_urls": self.MAX_URLS,
                "request_timeout_seconds": self.REQUEST_TIMEOUT,
            },
        }
