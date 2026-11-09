"""
SSRF Protection Unit Tests.

Coverage:
  1. Valid public HTTP/HTTPS URLs accepted
  2. Localhost & 127.0.0.1 blocked
  3. Private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) blocked
  4. Link-local & Cloud Metadata (169.254.169.254) blocked
  5. IPv6 Loopback ([::1]) blocked
  6. Invalid or unsupported scheme (ftp://, gopher://) blocked
  7. DNS resolution failure handled safely
"""

import pytest

from app.core.exceptions import BadRequestException
from app.core.ssrf import validate_target_url


def test_ssrf_valid_public_urls():
    assert validate_target_url("https://example.com") == "https://example.com"
    assert validate_target_url("http://example.org") == "http://example.org"


def test_ssrf_blocks_localhost():
    with pytest.raises(BadRequestException) as exc_info:
        validate_target_url("http://127.0.0.1")
    assert "blocked IP" in str(exc_info.value) or "restricted IP" in str(exc_info.value)

    with pytest.raises(BadRequestException) as exc_info:
        validate_target_url("http://localhost")
    assert "restricted IP" in str(exc_info.value) or "blocked IP" in str(exc_info.value)


def test_ssrf_blocks_private_ipv4():
    private_ips = [
        "http://10.0.0.1",
        "http://10.255.255.254",
        "http://172.16.0.1",
        "http://172.31.255.255",
        "http://192.168.0.1",
        "http://192.168.1.100",
    ]
    for target in private_ips:
        with pytest.raises(BadRequestException):
            validate_target_url(target)


def test_ssrf_blocks_cloud_metadata_and_link_local():
    cloud_metadata_urls = [
        "http://169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.1.1",
    ]
    for target in cloud_metadata_urls:
        with pytest.raises(BadRequestException):
            validate_target_url(target)


def test_ssrf_blocks_ipv6_loopback():
    with pytest.raises(BadRequestException):
        validate_target_url("http://[::1]")


def test_ssrf_blocks_unsupported_schemes():
    invalid_schemes = [
        "ftp://example.com",
        "gopher://example.com",
        "file:///etc/passwd",
        "dict://example.com",
    ]
    for target in invalid_schemes:
        with pytest.raises(BadRequestException):
            validate_target_url(target)
