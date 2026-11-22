"""
Stage 6.6: Google Safe Browsing
Checks URLs against the Google Safe Browsing Lookup API (v4).

Detects:
  - MALWARE: site distributing malware
  - SOCIAL_ENGINEERING: phishing and social engineering pages
  - UNWANTED_SOFTWARE: deceptive downloads, bundles
  - POTENTIALLY_HARMFUL_APPLICATION: malicious mobile/desktop apps

Requires env var SAFE_BROWSING_API_KEY (or GOOGLE_SAFE_BROWSING_KEY).
Can be acquired for free from the Google Cloud Console.
"""
import os
import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

THREAT_DESCRIPTIONS = {
    "MALWARE": "Malware distribution site",
    "SOCIAL_ENGINEERING": "Phishing / Social Engineering page",
    "UNWANTED_SOFTWARE": "Deceptive or unwanted software installer",
    "POTENTIALLY_HARMFUL_APPLICATION": "Potentially harmful application (PHA)",
}


def _clean_error(e: Exception) -> str:
    msg = str(e)
    if isinstance(e, requests.exceptions.ConnectionError):
        if "NameResolutionError" in msg or "Failed to resolve" in msg:
            return "Could not resolve Google Safe Browsing API server (DNS/network unavailable)"
        if "RemoteDisconnected" in msg or "Connection aborted" in msg:
            return "Google Safe Browsing closed connection without responding"
    if isinstance(e, requests.exceptions.Timeout):
        return "Connection to Google Safe Browsing timed out"
    return msg


def check_safe_browsing(url: str, timeout: float = 6.0) -> dict:
    """
    Checks if a URL is listed in Google Safe Browsing.

    Returns:
        matched: bool (True if flagged as a threat)
        threat_types: list[str] (e.g. ["SOCIAL_ENGINEERING", "MALWARE"])
        threat_descriptions: list[str] human-readable threat descriptions
        platforms: list[str] targeted platforms
        error: error string if check failed or key is missing
        skipped: bool
    """
    if not url:
        return {"matched": False, "threat_types": [], "error": "No URL provided", "skipped": True}

    api_key = (
        os.environ.get("SAFE_BROWSING_API_KEY", "")
        or os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
        or os.environ.get("GSB_API_KEY", "")
    ).strip()

    if not api_key:
        return {
            "matched": False,
            "threat_types": [],
            "threat_descriptions": [],
            "platforms": [],
            "error": "SAFE_BROWSING_API_KEY not configured",
            "skipped": True,
        }

    payload = {
        "client": {
            "clientId": "hawkeyes-threat-scanner",
            "clientVersion": "2.0.0",
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            f"{GSB_API_URL}?key={api_key}",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )

        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            if not matches:
                return {
                    "matched": False,
                    "threat_types": [],
                    "threat_descriptions": [],
                    "platforms": [],
                    "error": None,
                    "skipped": False,
                }

            threat_types = sorted(list(set(m.get("threatType") for m in matches if m.get("threatType"))))
            platforms = sorted(list(set(m.get("platformType") for m in matches if m.get("platformType"))))
            descriptions = [THREAT_DESCRIPTIONS.get(t, t) for t in threat_types]

            return {
                "matched": True,
                "threat_types": threat_types,
                "threat_descriptions": descriptions,
                "platforms": platforms,
                "matches": matches,
                "error": None,
                "skipped": False,
            }
        elif resp.status_code == 400:
            return {
                "matched": False,
                "threat_types": [],
                "error": "Invalid Safe Browsing API key or request payload",
                "skipped": False,
            }
        elif resp.status_code == 403:
            return {
                "matched": False,
                "threat_types": [],
                "error": "Safe Browsing API key denied or billing/quota not active",
                "skipped": False,
            }
        else:
            return {
                "matched": False,
                "threat_types": [],
                "error": f"Safe Browsing HTTP {resp.status_code}: {resp.text[:120]}",
                "skipped": False,
            }

    except requests.RequestException as e:
        return {
            "matched": False,
            "threat_types": [],
            "error": f"Safe Browsing connection failed: {_clean_error(e)}",
            "skipped": False,
        }


if __name__ == "__main__":
    import json
    import sys

    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://malware.testing.google.test/testing/malware/"
    print(json.dumps(check_safe_browsing(test_url), indent=2))

