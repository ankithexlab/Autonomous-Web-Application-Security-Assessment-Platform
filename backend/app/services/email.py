"""
Email service for sending transactional emails.

Uses SMTP (Gmail) for sending password reset emails.
Falls back to console logging if SMTP credentials are not configured,
making local development seamless without requiring real email setup.

Setup for Gmail:
  1. Enable 2-Factor Authentication on your Google account
  2. Go to https://myaccount.google.com/apppasswords
  3. Generate an App Password for "Mail"
  4. Set SMTP_USERNAME and SMTP_PASSWORD in backend/.env
"""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.config import get_settings

logger = logging.getLogger("awsap.email")


class EmailService:
    """Transactional email sender using SMTP (Gmail)."""

    def __init__(self) -> None:
        self._settings = get_settings()

    @property
    def _is_configured(self) -> bool:
        """Check if SMTP credentials are set."""
        return bool(self._settings.SMTP_USERNAME and self._settings.SMTP_PASSWORD)

    def _send_smtp(self, to_email: str, subject: str, html_body: str) -> None:
        """Send an email via SMTP (Gmail)."""
        settings = self._settings

        msg = MIMEMultipart("alternative")
        msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_USERNAME}>"
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USERNAME, to_email, msg.as_string())

        logger.info("Email sent successfully to %s", to_email)

    def send_password_reset_email(self, to_email: str, reset_token: str) -> None:
        """
        Send a password reset email with a clickable link.

        Args:
            to_email: Recipient's email address.
            reset_token: JWT reset token to embed in the link.
        """
        settings = self._settings
        reset_url = f"{settings.FRONTEND_URL}/auth/reset-password?token={reset_token}"

        subject = "AWASAP — Reset Your Password"
        html_body = self._build_reset_email_html(to_email, reset_url)

        if self._is_configured:
            try:
                self._send_smtp(to_email, subject, html_body)
            except Exception as e:
                logger.error("Failed to send email to %s: %s", to_email, e)
                raise
        else:
            # Fallback: log to console for development
            logger.warning(
                "SMTP not configured — printing reset link to console.\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "  TO:    %s\n"
                "  LINK:  %s\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                to_email,
                reset_url,
            )

    @staticmethod
    def _build_reset_email_html(to_email: str, reset_url: str) -> str:
        """Build a professional HTML email template for password reset."""
        return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
</head>
<body style="margin:0;padding:0;background-color:#0f172a;font-family:'Segoe UI',Roboto,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#0f172a;">
    <tr>
      <td align="center" style="padding:40px 20px;">
        <table role="presentation" width="480" cellpadding="0" cellspacing="0"
               style="background-color:#1e293b;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.3);">
          <!-- Header -->
          <tr>
            <td style="padding:32px 32px 0;text-align:center;">
              <div style="display:inline-block;background:linear-gradient(135deg,#6366f1,#8b5cf6);
                          border-radius:12px;padding:12px 20px;margin-bottom:24px;">
                <span style="color:#fff;font-size:20px;font-weight:700;letter-spacing:1px;">🛡️ AWASAP</span>
              </div>
              <h1 style="color:#f1f5f9;font-size:22px;margin:0 0 8px;">Password Reset Request</h1>
              <p style="color:#94a3b8;font-size:14px;margin:0;">
                We received a request to reset your password
              </p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:24px 32px;">
              <p style="color:#cbd5e1;font-size:14px;line-height:1.6;margin:0 0 20px;">
                Hello <strong style="color:#f1f5f9;">{to_email}</strong>,
              </p>
              <p style="color:#cbd5e1;font-size:14px;line-height:1.6;margin:0 0 24px;">
                Click the button below to reset your password. This link is valid for
                <strong style="color:#f1f5f9;">30 minutes</strong>.
              </p>

              <!-- CTA Button -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center">
                    <a href="{reset_url}"
                       style="display:inline-block;background:linear-gradient(135deg,#6366f1,#8b5cf6);
                              color:#fff;text-decoration:none;font-size:15px;font-weight:600;
                              padding:14px 36px;border-radius:10px;letter-spacing:0.5px;">
                      Reset My Password
                    </a>
                  </td>
                </tr>
              </table>

              <p style="color:#64748b;font-size:12px;line-height:1.6;margin:24px 0 0;text-align:center;">
                If you didn't request this, you can safely ignore this email.
                Your password will remain unchanged.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:20px 32px;border-top:1px solid #334155;text-align:center;">
              <p style="color:#475569;font-size:11px;margin:0;">
                &copy; 2026 AWASAP — Autonomous Web Application Security Assessment Platform
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


# ── Module-level singleton ───────────────────────────────────────

email_service = EmailService()
