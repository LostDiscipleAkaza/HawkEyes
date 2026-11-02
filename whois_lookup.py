"""
Stage 4: WHOIS / RDAP
Domain registration metadata. Domain age is one of the strongest single
signals for phishing: freshly-registered domains are disproportionately
malicious.
"""
from datetime import datetime, timezone

import whois as pywhois


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _to_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def lookup_whois(registered_domain: str) -> dict:
    if not registered_domain:
        return {"error": "no registered domain"}

    try:
        w = pywhois.whois(registered_domain)
        creation_date = _to_utc(_first(w.creation_date))
        expiration_date = _first(w.expiration_date)
        age_days = (datetime.now(timezone.utc) - creation_date).days if creation_date else None

        return {
            "registrar": w.registrar,
            "creation_date": creation_date.isoformat() if creation_date else None,
            "expiration_date": str(expiration_date) if expiration_date else None,
            "age_days": age_days,
            "name_servers": w.name_servers,
            "org": w.org,
            "country": w.country,
        }
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    import json
    import sys

    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(lookup_whois(domain), indent=2))
