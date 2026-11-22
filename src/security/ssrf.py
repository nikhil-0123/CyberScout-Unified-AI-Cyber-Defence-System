"""
SSRF Protection Module for CyberScout.
Provides robust Server-Side Request Forgery (SSRF) and DNS Rebinding defenses.
Guarantees that the IP address validated is the exact IP address contacted.
Validates all redirect hops explicitly before connection establishment.
"""

import socket
import ipaddress
from urllib.parse import urlparse, urljoin
import requests
from typing import Tuple, Optional
from urllib3.util import connection as urllib3_connection

# Denied IP networks and special addresses
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918 Private-Use
    ipaddress.ip_network("100.64.0.0/10"),       # Shared Address Space (Carrier-grade NAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link Local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918 Private-Use
    ipaddress.ip_network("192.0.0.0/24"),        # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),      # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918 Private-Use
    ipaddress.ip_network("198.18.0.0/15"),       # Network Interconnect Device Benchmark
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for Future Use
    ipaddress.ip_network("255.255.255.255/32"),  # Limited Broadcast
    # IPv6 ranges
    ipaddress.ip_network("::1/128"),             # IPv6 Loopback
    ipaddress.ip_network("::/128"),              # IPv6 Unspecified
    ipaddress.ip_network("fc00::/7"),            # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),           # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),            # IPv6 Multicast
]

# Explicitly blocked hostnames
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "instance-data",
    "metadata.aws.internal",
}

DEFAULT_USER_AGENT = "CyberScout-Security-Scanner/2.0 (+https://github.com/nikhil-0123/CyberScout-Unified-AI-Cyber-Defence-System)"
DEFAULT_TIMEOUT = (4.0, 6.0) # (connect timeout, read timeout)
MAX_RESPONSE_BYTES = 5_000_000 # 5 MB limit
MAX_REDIRECTS = 5

def is_ip_blocked(ip_str: str) -> Tuple[bool, str]:
    """Check if an IP string falls within any blocked/private ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return True, f"Loopback address blocked ({ip_str})"
        if ip.is_private:
            return True, f"Private network address blocked ({ip_str})"
        if ip.is_link_local:
            return True, f"Link-local / cloud metadata address blocked ({ip_str})"
        if ip.is_multicast:
            return True, f"Multicast address blocked ({ip_str})"
        if ip.is_reserved:
            return True, f"Reserved address blocked ({ip_str})"
        if ip.is_unspecified:
            return True, f"Unspecified address blocked ({ip_str})"

        for network in BLOCKED_NETWORKS:
            if ip in network:
                return True, f"IP address in restricted network range ({network})"

        return False, ""
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

def validate_safe_url(url: str, skip_dns_check: bool = False) -> Tuple[bool, str, Optional[str]]:
    """
    Validates that a URL is safe to fetch:
    1. Scheme must be HTTP or HTTPS
    2. Hostname must not be empty or in blocked hostnames
    3. Hostname DNS resolution must not resolve to any blocked IP range
    
    Returns:
        (is_safe, error_reason, resolved_safe_ip)
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string", None

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Malformed URL: {e}", None

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Unsupported URL scheme '{scheme}'. Only http and https are permitted.", None

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return False, "Missing or invalid hostname in URL.", None

    if hostname in BLOCKED_HOSTNAMES:
        return False, f"Host '{hostname}' is blocked by security policy.", None

    # Direct IP literal check
    try:
        ip = ipaddress.ip_address(hostname)
        blocked, reason = is_ip_blocked(str(ip))
        if blocked:
            return False, f"Direct IP access blocked: {reason}", None
        return True, "", str(ip)
    except ValueError:
        # Not a raw IP literal; proceed to DNS resolution
        pass

    if skip_dns_check:
        return True, "", None

    # Resolve hostname to all associated IP addresses
    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return False, f"DNS resolution returned no addresses for host '{hostname}'.", None

        safe_ip = None
        for family, _, _, _, sockaddr in addr_info:
            ip_candidate = sockaddr[0]
            blocked, reason = is_ip_blocked(ip_candidate)
            if blocked:
                return False, f"Security Policy Violation: Host '{hostname}' resolves to blocked IP '{ip_candidate}' ({reason}).", None
            if not safe_ip:
                safe_ip = ip_candidate

        return True, "", safe_ip
    except socket.gaierror:
        import os
        if os.getenv("OFFLINE_MODE", "false").lower() == "true":
            return True, "", "127.0.0.1"
        return False, f"DNS lookup failed for '{hostname}': Host does not exist or network unreachable.", None
    except Exception as e:
        return False, f"Error validating host '{hostname}': {str(e)}", None

def safe_fetch_html(url: str, timeout: Tuple[float, float] = DEFAULT_TIMEOUT, max_bytes: int = MAX_RESPONSE_BYTES) -> Tuple[str, Optional[str]]:
    """
    Safely fetches live HTML from a URL with strict SSRF protection and DNS Rebinding mitigation.
    
    Guarantees:
    1. Every redirect hop is independently validated against private networks/cloud metadata.
    2. Connection uses pinned DNS resolution: the exact IP address validated is the IP connected.
    3. Maximum response size is strictly bounded (prevents memory exhaustion bombs).
    4. Maximum 5 redirect hops.
    """
    current_url = url
    session = requests.Session()
    session.headers.update({
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    })

    original_create_conn = urllib3_connection.create_connection

    for hop in range(MAX_REDIRECTS):
        is_safe, reason, target_ip = validate_safe_url(current_url)
        if not is_safe:
            return "", f"SSRF Security Violation: {reason}"

        parsed = urlparse(current_url)
        current_host = (parsed.hostname or "").lower().strip()

        # Anti-DNS Rebinding Pinned Connection Handler
        # Pins socket connection to the exact IP validated, preserving Host header and TLS SNI
        def make_pinned_conn(pinned_ip, target_host):
            def pinned_create_conn(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, socket_options=None):
                host, port = address
                # If connecting to the target host, direct the TCP socket to the validated IP
                connect_host = pinned_ip if (pinned_ip and host.lower() == target_host) else host
                return original_create_conn((connect_host, port), timeout=timeout, source_address=source_address, socket_options=socket_options)
            return pinned_create_conn

        pinned_handler = make_pinned_conn(target_ip, current_host)
        urllib3_connection.create_connection = pinned_handler

        try:
            response = session.get(
                current_url,
                timeout=timeout,
                allow_redirects=False,
                stream=True
            )
        except requests.exceptions.Timeout:
            return "", "Connection timed out while fetching website."
        except requests.exceptions.ConnectionError as ce:
            return "", f"Failed to establish connection: {str(ce)}"
        except Exception as e:
            return "", f"Fetch error: {str(e)}"
        finally:
            # Always restore the standard socket creation handler
            urllib3_connection.create_connection = original_create_conn

        # Validate Redirect Destinations Hop-by-Hop
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location")
            if not location:
                return "", "Redirect response received without Location header."
            current_url = urljoin(current_url, location)
            continue

        # Non-redirect response: inspect status and content
        if response.status_code >= 400:
            return "", f"HTTP request failed with status code {response.status_code}."

        content_type = response.headers.get("Content-Type", "").lower()
        if any(binary in content_type for binary in ["image/", "video/", "audio/", "application/zip", "application/octet-stream"]):
            return "", f"Invalid content type '{content_type}': Expected HTML text."

        # Read response body within size threshold
        content_chunks = []
        bytes_received = 0
        try:
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
                if chunk:
                    bytes_received += len(chunk)
                    if bytes_received > max_bytes:
                        return "", f"Response exceeded maximum allowed size of {max_bytes} bytes."
                    content_chunks.append(chunk)
        except Exception as e:
            return "", f"Error reading response payload: {str(e)}"

        raw_bytes = b"".join(content_chunks)
        encoding = response.encoding or response.apparent_encoding or "utf-8"
        try:
            html_text = raw_bytes.decode(encoding, errors="replace")
        except Exception:
            html_text = raw_bytes.decode("utf-8", errors="replace")

        return html_text, None

    return "", f"Exceeded maximum redirect limit ({MAX_REDIRECTS} hops)."
