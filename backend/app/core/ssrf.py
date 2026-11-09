"""
SSRF Protection Module.

Provides security-critical validation for target URLs before outbound HTTP requests
are executed by the scanner engine:
  1. Parses target URL and validates HTTP/HTTPS schemes.
  2. Resolves hostname to all target IPv4/IPv6 addresses.
  3. Validates each resolved IP against blacklisted private, loopback, link-local,
     multicast, reserved, and cloud metadata address ranges.
"""

import ipaddress
import socket
from urllib.parse import urlparse

from app.core.exceptions import BadRequestException


# Blacklisted IP Networks
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (default route)
    ipaddress.ip_network("127.0.0.0/8"),        # IPv4 Loopback
    ipaddress.ip_network("10.0.0.0/8"),         # Private-Use RFC1918
    ipaddress.ip_network("172.16.0.0/12"),      # Private-Use RFC1918
    ipaddress.ip_network("192.168.0.0/16"),     # Private-Use RFC1918
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Metadata (AWS 169.254.169.254)
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 Ranges
    ipaddress.ip_network("::1/128"),            # IPv6 Loopback
    ipaddress.ip_network("::/128"),             # IPv6 Unspecified
    ipaddress.ip_network("fc00::/7"),           # IPv6 Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # IPv6 Link-Local
    ipaddress.ip_network("ff00::/8"),           # IPv6 Multicast
]


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_local: bool = False) -> bool:
    """
    Check if an IP address falls within any blacklisted network range or reserved category.
    Cloud metadata (169.254.169.254) is strictly forbidden under all environments.
    """
    # Cloud metadata is strictly forbidden under all environments
    metadata_net = ipaddress.ip_network("169.254.0.0/16")
    if ip in metadata_net:
        return True

    from app.config import get_settings
    settings = get_settings()
    if allow_local or settings.ALLOW_LOCAL_TARGETS:
        # Only when explicitly permitted for authorized local labs, allow private/loopback
        return False

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True

    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True

    return False


def validate_target_url(url: str) -> str:
    """
    Validate target URL against SSRF hazards.

    Raises BadRequestException if:
      - Scheme is not http or https
      - Hostname is empty or invalid
      - Hostname resolves to loopback, private, link-local, or cloud metadata IP
    Returns normalized target URL on success.
    """
    if not url:
        raise BadRequestException("Target URL cannot be empty.")

    # Ensure URL has a scheme for parsing
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise BadRequestException(f"Unsupported URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

    if parsed.username or parsed.password:
        raise BadRequestException("Target URL containing embedded user credentials (userinfo) is not permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise BadRequestException("Target URL does not contain a valid hostname.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Check if hostname is directly an IP address
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_ip_blocked(ip_obj):
            raise BadRequestException(f"Target URL resolves to blocked IP address '{hostname}'. Access denied.")
        return url
    except ValueError:
        # Not a raw IP, proceed to DNS resolution
        pass

    # Reject known cloud metadata hostnames directly
    lower_host = hostname.lower()
    if lower_host in ("metadata.google.internal", "instance-data", "metadata"):
        raise BadRequestException(f"Target hostname '{hostname}' is a restricted host. Access denied for SSRF protection.")

    # Resolve hostname via socket DNS lookup (dual-query rebinding mitigation)
    try:
        addr_info_1 = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise BadRequestException(f"DNS resolution failed for hostname '{hostname}': {e.strerror}")
    except Exception as e:
        raise BadRequestException(f"Failed to resolve target hostname '{hostname}': {e}")

    if not addr_info_1:
        raise BadRequestException(f"DNS resolution returned no IP addresses for hostname '{hostname}'.")

    # Second resolution to detect rapid DNS rebinding / zero-TTL flips
    try:
        addr_info_2 = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception:
        addr_info_2 = addr_info_1

    # Check all resolved IP addresses across both resolution passes
    resolved_ips = set()
    for addr_info in (addr_info_1, addr_info_2):
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip_str = sockaddr[0]
            resolved_ips.add(ip_str)
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if is_ip_blocked(ip_obj):
                    raise BadRequestException(
                        f"Target hostname '{hostname}' resolved to restricted IP address '{ip_str}'. Access denied for SSRF protection."
                    )
            except ValueError:
                continue

    return url
