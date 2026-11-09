"""
Evidence & Input Sanitization for Sentinel AI.

Masks tokens, authorization headers, passwords, cookies, and API keys.
Neutralizes prompt injection signatures attempting system override or role hijacking.
Wraps untrusted evidence in structured boundary tags.
"""

import re


def sanitize_sensitive_secrets(text: str | None) -> str | None:
    """Mask tokens, authorization headers, passwords, cookies, and API keys."""
    if not text:
        return text

    sanitized = re.sub(r"(?i)authorization\s*:\s*bearer\s+[^\s;\r\n]+", "Authorization: Bearer [REDACTED]", text)
    sanitized = re.sub(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{10,}", "Bearer [REDACTED]", sanitized)
    sanitized = re.sub(r"(?i)(token|secret|password|api[_-]?key)\s*[:=]\s*['\"]?[^\s'\";]+", r"\1: [REDACTED]", sanitized)
    sanitized = re.sub(r"(?i)cookie\s*:\s*[^\r\n]+", "Cookie: [REDACTED]", sanitized)
    sanitized = re.sub(r"(?i)\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]+\b", "[REDACTED_JWT]", sanitized)
    return sanitized


def defend_prompt_injection(text: str | None) -> str | None:
    """Neutralize prompt injection signatures attempting system override or role hijacking."""
    if not text:
        return text

    patterns = [
        r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions",
        r"(?i)disregard\s+(all\s+)?(previous|prior)\s+instructions",
        r"(?i)system\s+prompt\s*:",
        r"(?i)you\s+are\s+now\s+an?\s+unrestricted",
        r"(?i)override\s+system\s+instructions",
        r"(?i)dan\s+mode",
        r"(?i)jailbreak",
        r"(?i)developer\s+mode\s+output",
    ]
    sanitized = text
    for pattern in patterns:
        sanitized = re.sub(pattern, "[BLOCKED_PROMPT_INJECTION_ATTEMPT]", sanitized)
    return sanitized


def sanitize_user_input(text: str | None, max_length: int = 2000) -> str:
    """Sanitize interactive user chat messages without structural XML tags."""
    if not text:
        return ""
    cleaned = sanitize_sensitive_secrets(text) or ""
    cleaned = defend_prompt_injection(cleaned) or ""
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "... [TRUNCATED_FOR_LENGTH]"
    return cleaned


def sanitize_evidence_text(text: str | None, max_length: int = 1500) -> str | None:
    """Sanitize untrusted target response evidence and wrap in XML framing."""
    if not text:
        return text

    cleaned = sanitize_sensitive_secrets(text) or ""
    cleaned = defend_prompt_injection(cleaned) or ""
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "... [TRUNCATED]"

    return f"<untrusted_evidence>\n{cleaned}\n</untrusted_evidence>"
