"""
Stage 3.5: Certificate Transparency (CT)
Queries public Certificate Transparency (CT) logs (via crt.sh) to discover:
  - Historical certificate issuance patterns and longevity
  - Certificate churn / rapid re-issuance (a frequent indicator of phishing infrastructure)
  - Discovered subdomains and wildcard certificates
  - Certificate Authorities (CAs) used over time
  - First-seen vs most-recent issuance dates
"""
from datetime import datetime, timezone
import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

CRT_SH_API = "https://crt.sh/"

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "application/json",
}


def _parse_iso(date_str: str):
    if not date_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str.split(".")[0], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _clean_error(e: Exception) -> str:
    msg = str(e)
    if isinstance(e, requests.exceptions.ConnectionError):
        if "NameResolutionError" in msg or "Failed to resolve" in msg:
            return "Could not resolve Certificate Transparency log server (DNS/network unavailable)"
        if "RemoteDisconnected" in msg or "Connection aborted" in msg:
            return "CT log server closed connection without responding"
    if isinstance(e, requests.exceptions.Timeout):
        return "Certificate Transparency lookup timed out"
    return msg


def check_certificate_transparency(domain: str, timeout: float = 6.0) -> dict:
    """
    Queries crt.sh for CT log records associated with the registered domain.

    Returns:
        total_certs: int
        first_seen: str (ISO)
        last_seen: str (ISO)
        history_days: int (longevity in CT logs)
        unique_issuers: list[str]
        discovered_subdomains: list[str]
        wildcard_count: int
        recent_certs_7d: int
        recent_certs_30d: int
        flags: list[str]
        risk_score: int (0-30)
        error: str or None
    """
    clean_domain = (domain or "").strip().lower()
    if not clean_domain or clean_domain in ("localhost", "127.0.0.1"):
        return {
            "total_certs": 0,
            "first_seen": None,
            "last_seen": None,
            "history_days": None,
            "unique_issuers": [],
            "discovered_subdomains": [],
            "wildcard_count": 0,
            "recent_certs_7d": 0,
            "recent_certs_30d": 0,
            "flags": [],
            "risk_score": 0,
            "error": "No valid domain to query",
        }

    flags = []
    risk_score = 0

    try:
        resp = requests.get(
            CRT_SH_API,
            params={"q": f"%.{clean_domain}", "output": "json"},
            headers=DEFAULT_HEADERS,
            timeout=timeout,
        )

        if resp.status_code != 200:
            return {
                "total_certs": 0,
                "first_seen": None,
                "last_seen": None,
                "history_days": None,
                "unique_issuers": [],
                "discovered_subdomains": [],
                "wildcard_count": 0,
                "recent_certs_7d": 0,
                "recent_certs_30d": 0,
                "flags": [],
                "risk_score": 0,
                "error": f"crt.sh returned HTTP {resp.status_code}",
            }

        entries = resp.json()
        if not entries or not isinstance(entries, list):
            flags.append("No Certificate Transparency logs found for this domain")
            return {
                "total_certs": 0,
                "first_seen": None,
                "last_seen": None,
                "history_days": None,
                "unique_issuers": [],
                "discovered_subdomains": [],
                "wildcard_count": 0,
                "recent_certs_7d": 0,
                "recent_certs_30d": 0,
                "flags": flags,
                "risk_score": 5,
                "error": None,
            }

        now = datetime.now(timezone.utc)
        earliest_dt = None
        latest_dt = None
        issuers = set()
        subdomains = set()
        wildcards = 0
        recent_7d = 0
        recent_30d = 0

        for entry in entries:
            # Parse not_before date
            dt = _parse_iso(entry.get("not_before")) or _parse_iso(entry.get("entry_timestamp"))
            if dt:
                if earliest_dt is None or dt < earliest_dt:
                    earliest_dt = dt
                if latest_dt is None or dt > latest_dt:
                    latest_dt = dt

                age_days = (now - dt).days
                if 0 <= age_days <= 7:
                    recent_7d += 1
                if 0 <= age_days <= 30:
                    recent_30d += 1

            # Issuer
            issuer_name = entry.get("issuer_name", "")
            # Extract common CA org name if available
            if "O=" in issuer_name:
                ca_org = issuer_name.split("O=")[1].split(",")[0].strip('"')
                issuers.add(ca_org)
            elif "CN=" in issuer_name:
                ca_cn = issuer_name.split("CN=")[1].split(",")[0].strip('"')
                issuers.add(ca_cn)

            # Subdomain discovery via common_name and name_value
            names = (entry.get("name_value") or "").split("\n")
            cn = entry.get("common_name")
            if cn:
                names.append(cn)

            for name in names:
                name = name.strip().lower()
                if not name:
                    continue
                if name.startswith("*."):
                    wildcards += 1
                    name = name[2:]
                if name.endswith("." + clean_domain) or name == clean_domain:
                    subdomains.add(name)

        history_days = (latest_dt - earliest_dt).days if (earliest_dt and latest_dt) else None

        # Analyze risk factors
        if earliest_dt:
            total_age_from_first = (now - earliest_dt).days
            if total_age_from_first <= 7:
                flags.append(f"Brand-new certificate footprint: first logged in CT {total_age_from_first} day(s) ago")
                risk_score += 20
            elif total_age_from_first <= 30:
                flags.append(f"Recent certificate presence: first seen in CT logs {total_age_from_first} days ago")
                risk_score += 10

        if recent_7d >= 10:
            flags.append(f"High certificate churn: {recent_7d} certificates issued in the past 7 days")
            risk_score += 15

        return {
            "total_certs": len(entries),
            "first_seen": earliest_dt.isoformat() if earliest_dt else None,
            "last_seen": latest_dt.isoformat() if latest_dt else None,
            "history_days": history_days,
            "unique_issuers": sorted(list(issuers)),
            "discovered_subdomains": sorted(list(subdomains))[:20],
            "wildcard_count": wildcards,
            "recent_certs_7d": recent_7d,
            "recent_certs_30d": recent_30d,
            "flags": flags,
            "risk_score": min(risk_score, 40),
            "error": None,
        }

    except requests.RequestException as e:
        return {
            "total_certs": 0,
            "first_seen": None,
            "last_seen": None,
            "history_days": None,
            "unique_issuers": [],
            "discovered_subdomains": [],
            "wildcard_count": 0,
            "recent_certs_7d": 0,
            "recent_certs_30d": 0,
            "flags": [],
            "risk_score": 0,
            "error": f"CT log check failed: {_clean_error(e)}",
        }


if __name__ == "__main__":
    import json
    import sys

    test_domain = sys.argv[1] if len(sys.argv) > 1 else "github.com"
    print(json.dumps(check_certificate_transparency(test_domain), indent=2))

