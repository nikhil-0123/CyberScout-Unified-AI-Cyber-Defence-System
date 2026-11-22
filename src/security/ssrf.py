"""
SSRF Protection Module for CyberScout.
Validates outbound URLs to prevent Server-Side Request Forgery (SSRF)
against loopback, private networks, cloud metadata services, and non-HTTP protocols.
"""

import socket
import ipaddress
from urllib.parse import urlparse, urljoin
import requests
from typing import Tuple, Optional

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
}

DEFAULT_USER_AGENT = "CyberScout-Security-Scanner/1.0 (+https://github.com/nikhil-0123/CyberScout-Unified-AI-Cyber-Defence-System)"
DEFAULT_TIMEOUT = (5.0, 8.0) # (connect timeout, read timeout)
MAX_RESPONSE_BYTES = 5_000_000 # 5 MB limit to prevent memory exhaustion / decompression bombs
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

def validate_safe_url(url: str, skip_dns_check: bool = False) -> Tuple[bool, str]:
    """
    Validates that a URL is safe to fetch:
    1. Scheme must be HTTP or HTTPS
    2. Hostname must not be empty or in blocked hostnames
    3. Hostname DNS resolution must not resolve to any blocked IP range
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string"

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Malformed URL: {e}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Unsupported URL scheme '{scheme}'. Only http and https are permitted."

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return False, "Missing or invalid hostname in URL."

    if hostname in BLOCKED_HOSTNAMES:
        return False, f"Host '{hostname}' is blocked by security policy."

    # Direct IP literal check
    try:
        ip = ipaddress.ip_address(hostname)
        blocked, reason = is_ip_blocked(str(ip))
        if blocked:
            return False, f"Direct IP access blocked: {reason}"
        return True, ""
    except ValueError:
        # Not a raw IP literal; proceed to DNS resolution
        pass

    if skip_dns_check:
        return True, ""

    # Resolve hostname to all associated IP addresses
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return False, f"DNS resolution returned no addresses for host '{hostname}'."

        for family, _, _, _, sockaddr in addr_info:
            ip_candidate = sockaddr[0]
            blocked, reason = is_ip_blocked(ip_candidate)
            if blocked:
                return False, f"Security Policy Violation: Host '{hostname}' resolves to blocked IP '{ip_candidate}' ({reason})."

        return True, ""
    except socket.gaierror as e:
        # If in offline sandbox/test mode or host is a well-formed domain, handle gracefully
        import os
        if os.getenv("OFFLINE_MODE", "false").lower() == "true":
            return True, ""
        return False, f"DNS lookup failed for '{hostname}': Host does not exist or network unreachable."
    except Exception as e:
        return False, f"Error validating host '{hostname}': {str(e)}"

def safe_fetch_html(url: str, timeout: Tuple[float, float] = DEFAULT_TIMEOUT, max_bytes: int = MAX_RESPONSE_BYTES) -> Tuple[str, Optional[str]]:
    """
    Safely fetches live HTML from a URL with SSRF protection, redirect verification,
    and size bounds.
    
    Returns:
        (html_content, error_message)
        If successful: (html_string, None)
        If failed: ("", error_description_string)
    """
    current_url = url
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    for hop in range(MAX_REDIRECTS):
        is_safe, reason = validate_safe_url(current_url)
        if not is_safe:
            return "", f"SSRF Guard: {reason}"

        try:
            # stream=True to guard against huge payload downloads
            response = session.get(
                current_url,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
                headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
            )

            # Check for redirect
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    return "", "Redirect response received without Location header."
                current_url = urljoin(current_url, location)
                continue

            # Check HTTP status
            if response.status_code >= 400:
                return "", f"HTTP request failed with status code {response.status_code}."

            # Verify Content-Type if present (warn if binary, but permit text/html)
            content_type = response.headers.get("Content-Type", "").lower()
            if any(binary in content_type for binary in ["image/", "video/", "audio/", "application/zip", "application/octet-stream"]):
                return "", f"Invalid content type '{content_type}': Expected HTML text."

            # Stream chunks with strict byte limit
            content_chunks = []
            bytes_received = 0
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
                if chunk:
                    bytes_received += len(chunk)
                    if bytes_received > max_bytes:
                        return "", f"Response exceeded maximum allowed size of {max_bytes} bytes."
                    content_chunks.append(chunk)

            raw_bytes = b"".join(content_chunks)
            encoding = response.encoding or response.apparent_encoding or "utf-8"
            try:
                html_text = raw_bytes.decode(encoding, errors="replace")
            except Exception:
                html_text = raw_bytes.decode("utf-8", errors="replace")

            return html_text, None

        except requests.exceptions.Timeout:
            return "", "Connection timed out while fetching website."
        except requests.exceptions.ConnectionError:
            return "", "Failed to establish connection. Target host may be down or unreachable."
        except Exception as e:
            return "", f"Fetch error: {str(e)}"

    return "", f"Exceeded maximum redirect limit ({MAX_REDIRECTS} hops)."
