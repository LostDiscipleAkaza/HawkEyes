"""
HawkEyes SSRF (Server-Side Request Forgery) & Private IP Protection
Prevents scanner misuse against internal networks, loopback addresses,
RFC 1918 private subnets, and cloud metadata services (e.g. AWS 169.254.169.254).
"""
import ipaddress
import os
import socket
from urllib.parse import urlparse

SAFE_SCHEMES = {"http", "https"}

# Cloud metadata endpoints and reserved special ranges
BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "instance-data",
}


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Checks whether an IP string is private, loopback, link-local, multicast, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def _try_parse_custom_ip(host: str):
    """Parses Dword, Hex, and Octal IP representations into an IPv4Address."""
    if not host:
        return None
    h = host.strip("[]").strip()
    if h.isdigit():
        try:
            val = int(h)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass
    if h.lower().startswith("0x"):
        try:
            val = int(h, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass
    parts = h.split(".")
    if 2 <= len(parts) <= 4:
        try:
            nums = []
            for p in parts:
                if p.lower().startswith("0x"):
                    nums.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1 and p.isdigit():
                    nums.append(int(p, 8))
                elif p.isdigit():
                    nums.append(int(p))
                else:
                    return None
            if len(nums) == 4 and all(0 <= n <= 255 for n in nums):
                return ipaddress.IPv4Address(bytes(nums))
            elif len(nums) == 2:
                val = (nums[0] << 24) | nums[1]
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass
    return None


def is_safe_url(url: str, allow_private: bool = None) -> tuple[bool, str | None]:
    """
    Validates that a URL is safe to query over the public internet.

    Returns:
        (is_safe: bool, reason: str | None)
    """
    if allow_private is None:
        allow_private = os.environ.get("HAWKEYES_ALLOW_PRIVATE_IPS", "0").lower() in ("1", "true", "yes")

    if allow_private:
        return True, None

    if not url or not isinstance(url, str):
        return False, "Invalid or empty URL"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed URL structure"

    # 1. Scheme validation (block file://, gopher://, dict://, etc.)
    scheme = (parsed.scheme or "").lower()
    if scheme not in SAFE_SCHEMES:
        return False, f"Prohibited URL scheme '{scheme}' (only HTTP/HTTPS allowed)"

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return False, "URL contains no valid host"

    # 2. Blocked hostnames (localhost, cloud metadata aliases)
    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".localhost"):
        return False, f"Prohibited internal host '{hostname}' (SSRF protection)"

    # 3. Check if hostname is directly an IP literal or obfuscated IP
    clean_host = hostname.strip("[]")
    if is_private_or_reserved_ip(clean_host):
        return False, f"Prohibited private/internal IP address '{clean_host}' (SSRF protection)"

    custom_ip = _try_parse_custom_ip(clean_host)
    if custom_ip and is_private_or_reserved_ip(str(custom_ip)):
        return False, f"Prohibited encoded internal IP '{clean_host}' -> '{custom_ip}' (SSRF protection)"

    # 4. Resolve hostname via DNS and check all returned IP addresses
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = {item[4][0] for item in addr_info}
        for ip in resolved_ips:
            if is_private_or_reserved_ip(ip):
                return False, f"Host '{hostname}' resolves to private/internal IP '{ip}' (SSRF protection)"
    except socket.gaierror:
        # Host doesn't resolve — not an active private IP threat, can proceed to standard error handling
        pass
    except Exception as e:
        return False, f"DNS validation failed for '{hostname}': {e}"

    return True, None


if __name__ == "__main__":
    test_urls = [
        "http://127.0.0.1:8080",
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://2130706433/",  # 127.0.0.1 in dword
        "http://192.168.1.1/",
        "https://google.com",
    ]
    for u in test_urls:
        safe, reason = is_safe_url(u)
        print(f"{u:<45} -> {'SAFE' if safe else 'BLOCKED: ' + reason}")
