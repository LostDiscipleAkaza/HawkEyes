"""
Stage 2: DNS
Resolves common record types. Missing/empty records are a useful signal
on their own (parked or dead domains resolve nothing) - but only when
queried against the right target.

MX and NS records almost always live at the zone APEX (e.g. "example.com"),
not on a subdomain like "www.example.com" - mail routing and delegation
are configured at the root, not per-subdomain. Querying them against a
subdomain returns empty for the vast majority of real sites even when the
domain is perfectly healthy, which looks like a red flag but isn't one.

So: A / AAAA / TXT are queried against the exact hostname given (these
genuinely can differ per-subdomain). MX / NS are queried against the
registered/apex domain instead.
"""
import dns.resolver

HOST_RECORD_TYPES = ["A", "AAAA", "TXT"]
APEX_RECORD_TYPES = ["MX", "NS"]
ALL_RECORD_TYPES = HOST_RECORD_TYPES + APEX_RECORD_TYPES


def _resolve_one(resolver, name, record_type):
    try:
        answers = resolver.resolve(name, record_type)
        return [r.to_text() for r in answers]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []
    except Exception as e:
        return [f"error: {e}"]


def lookup_dns(hostname: str, registered_domain: str = None, timeout: float = 5.0) -> dict:
    if not hostname:
        return {rt: [] for rt in ALL_RECORD_TYPES}

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    results = {}
    for record_type in HOST_RECORD_TYPES:
        results[record_type] = _resolve_one(resolver, hostname, record_type)

    # Fall back to the hostname itself if no apex domain was given (e.g.
    # hostname already IS the apex) or if it's the same as the hostname.
    apex = registered_domain or hostname
    for record_type in APEX_RECORD_TYPES:
        results[record_type] = _resolve_one(resolver, apex, record_type)

    return results


if __name__ == "__main__":
    import json
    import sys

    host = sys.argv[1] if len(sys.argv) > 1 else "www.example.com"
    apex = sys.argv[2] if len(sys.argv) > 2 else "example.com"
    print(json.dumps(lookup_dns(host, apex), indent=2))
