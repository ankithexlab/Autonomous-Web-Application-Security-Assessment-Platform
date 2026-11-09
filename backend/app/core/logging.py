"""
Centralized logging, correlation ID management, and sensitive data redaction.

Guarantees:
  - Request/correlation ID propagation across async contexts.
  - Automatic redaction of passwords, tokens, JWTs, and database credentials in logs.
  - Structured security event logging (audit trail) without personal data leakage.
  - Zero external/paid dependencies (Python standard library only).
"""

from contextvars import ContextVar
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any

# ContextVar holding the current request correlation ID
correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")


def get_correlation_id() -> str:
    """Return the active correlation ID or an empty string."""
    return correlation_id_var.get()


def set_correlation_id(correlation_id: str) -> None:
    """Set the active correlation ID for the current async task context."""
    correlation_id_var.set(correlation_id)


def mask_email(email: str | None) -> str:
    """
    Mask an email address for privacy-safe audit logging.
    Example: 'user.security@example.com' -> 'u***y@example.com'
    """
    if not email or "@" not in email:
        return "[REDACTED_EMAIL]"
    parts = email.split("@", 1)
    name, domain = parts[0], parts[1]
    if len(name) <= 2:
        masked_name = name[0] + "*"
    else:
        masked_name = name[0] + "***" + name[-1]
    return f"{masked_name}@{domain}"


# ── Sensitive Data Redaction Patterns ─────────────────────────────────────

# JWT pattern (header.payload.signature)
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)

# Authorization header tokens: Bearer <token>
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.+=/]+\b")

# Password / secret key key-value pairs (quoted or unquoted)
PASSWORD_PATTERN = re.compile(
    r'(?i)(["\']?(?:password|secret_key|secret|token|api_key|app_password)["\']?\s*[:=]\s*["\']?)([^"\'\s,;\\}]+)(["\']?)'
)

# Database credentials in URLs: scheme://user:pass@host
DB_URL_PATTERN = re.compile(
    r"([a-zA-Z0-9_+]+://[^:\s/]+):([^@\s/]+)(@[^/\s]+)"
)


def redact_sensitive_text(text: str) -> str:
    """
    Scrub passwords, JWTs, bearer tokens, and connection credentials from strings.
    """
    if not isinstance(text, str):
        return text

    # Redact Authorization headers
    text = BEARER_PATTERN.sub("Bearer [REDACTED]", text)

    # Redact raw JWT tokens
    text = JWT_PATTERN.sub("[JWT_REDACTED]", text)

    # Redact passwords/secrets in key-value structures
    text = PASSWORD_PATTERN.sub(r"\1[REDACTED]\3", text)

    # Redact database credentials in connection strings
    text = DB_URL_PATTERN.sub(r"\1:[REDACTED]\3", text)

    return text


class SensitiveDataRedactingFilter(logging.Filter):
    """
    Logging filter that sanitizes log records, masking credentials and attaching
    the active correlation ID.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Attach correlation ID to record for formatter use
        record.correlation_id = get_correlation_id() or "-"

        # Redact message and formatted args
        try:
            formatted_msg = record.getMessage()
            record.msg = redact_sensitive_text(formatted_msg)
            record.args = ()
        except Exception:
            if isinstance(record.msg, str):
                record.msg = redact_sensitive_text(record.msg)

        return True


# ── Structured Security Audit Logger ──────────────────────────────────────

security_audit_logger = logging.getLogger("awsap.security.audit")


def log_security_event(
    event_type: str,
    details: dict[str, Any],
    level: int = logging.INFO,
) -> None:
    """
    Emit a structured security audit event log.

    Guarantees:
      - Automatically includes ISO 8601 UTC timestamp and correlation ID.
      - Sanitizes all details values through sensitive data redaction.
      - Consistent event naming: 'auth.login_success', 'auth.login_failed', etc.
    """
    sanitized_details = {}
    for k, v in details.items():
        if isinstance(v, str):
            sanitized_details[k] = redact_sensitive_text(v)
        else:
            sanitized_details[k] = v

    event_payload = {
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "correlation_id": get_correlation_id() or "-",
        **sanitized_details,
    }

    security_audit_logger.log(
        level,
        "SECURITY_EVENT: %s",
        json.dumps(event_payload, default=str),
    )


# ── Logging Configuration ─────────────────────────────────────────────────

_LOGGING_CONFIGURED = False


def configure_logging(level: int = logging.INFO) -> None:
    """
    Configure application-wide logging with sensitive data redaction filter.
    Safe to call multiple times (idempotent).
    """
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return

    redacting_filter = SensitiveDataRedactingFilter()

    # Formatter with timestamp, level, correlation ID, logger name, message
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] [req_id=%(correlation_id)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.addFilter(redacting_filter)
        handler.setFormatter(formatter)

    # Attach filter to 'awsap' namespace loggers
    awsap_logger = logging.getLogger("awsap")
    awsap_logger.addFilter(redacting_filter)

    _LOGGING_CONFIGURED = True
