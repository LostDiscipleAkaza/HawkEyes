"""
Stage 7: urlscan.io
Submits the URL for a live, sandboxed scan and polls for the verdict.
This catches freshly-deployed phishing pages that VT hasn't indexed yet,
plus gives a screenshot of what the page actually looks like.
Requires env var URLSCAN_API_KEY (get one free at urlscan.io). Also reads
a .env file in the project folder if present, via python-dotenv.

Note: this is a live scan and takes several seconds to finish, so it is
opt-in (use_urlscan=True) rather than run on every request.

IMPORTANT: free urlscan.io API keys can only submit scans with
"visibility": "public" - "unlisted"/"private" require a paid plan and
a free key will get a 400 Bad Request if you request them. "public"
means the URL you scan and the result become visible in urlscan.io's
public search, so avoid using --scan on anything sensitive/internal.
"""
import os
import time

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed - fall back to real env vars only

URLSCAN_BASE = "https://urlscan.io/api/v1"


def _clean_error(e: Exception) -> str:
    msg = str(e)
    if isinstance(e, requests.exceptions.ConnectionError):
        if "NameResolutionError" in msg or "Failed to resolve" in msg:
            return "Could not resolve urlscan.io API (DNS/network unavailable)"
        if "RemoteDisconnected" in msg or "Connection aborted" in msg:
            return "urlscan.io closed connection without responding"
    if isinstance(e, requests.exceptions.Timeout):
        return "Connection to urlscan.io timed out"
    return msg


def check_urlscan(
    url: str,
    max_wait: float = 30.0,
    poll_interval: float = 3.5,
    timeout: float = 10.0,
    visibility: str = "public",
    wait_seconds: float = None,
) -> dict:
    if wait_seconds is not None:
        max_wait = wait_seconds

    api_key = os.environ.get("URLSCAN_API_KEY", "")
    if not api_key:
        return {"error": "URLSCAN_API_KEY not configured"}

    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    try:
        submit = requests.post(
            f"{URLSCAN_BASE}/scan/",
            headers=headers,
            json={"url": url, "visibility": visibility},
            timeout=timeout,
        )
        if submit.status_code == 400:
            return {
                "error": (
                    f"urlscan.io rejected the request (400). If you're on a free API key, "
                    f"visibility must be 'public' (got '{visibility}'); other causes: "
                    f"URL unreachable/invalid, or rate limit hit."
                )
            }
        if submit.status_code == 401:
            return {"error": "URLSCAN_API_KEY was rejected (401 Unauthorized) — check the key is correct and active"}
        if submit.status_code == 429:
            return {"error": "urlscan.io rate limit reached (429). Please wait before submitting more scans."}
        submit.raise_for_status()
        sub_data = submit.json()
        result_url = sub_data.get("api")
        uuid = sub_data.get("uuid")
        report_url = f"https://urlscan.io/result/{uuid}/" if uuid else None

        if max_wait <= 0 or not result_url:
            return {
                "status": "submitted",
                "message": "Scan submitted to urlscan.io; check back shortly",
                "result_url": result_url,
                "report_url": report_url,
            }

        # urlscan takes at least 8-10 seconds to spin up headless browser, load page, and screenshot
        waited = 0.0
        initial_sleep = min(8.0, max_wait)
        time.sleep(initial_sleep)
        waited += initial_sleep

        while waited <= max_wait:
            result = requests.get(result_url, timeout=timeout)
            if result.status_code == 200:
                data = result.json()
                verdicts = data.get("verdicts", {}).get("overall", {})
                return {
                    "malicious": verdicts.get("malicious", False),
                    "score": verdicts.get("score", 0),
                    "categories": verdicts.get("categories", []),
                    "screenshot": data.get("task", {}).get("screenshotURL"),
                    "report_url": data.get("task", {}).get("reportURL") or report_url,
                }
            elif result.status_code == 429:
                return {
                    "status": "rate_limited",
                    "error": "urlscan.io rate limit reached. Scan is queued; view report link shortly.",
                    "report_url": report_url,
                }

            if waited + poll_interval > max_wait:
                break
            time.sleep(poll_interval)
            waited += poll_interval

        return {
            "status": "pending",
            "message": f"Scan still processing after {int(waited)}s — use --full-scan or check report link",
            "result_url": result_url,
            "report_url": report_url,
        }
    except requests.RequestException as e:
        return {"error": _clean_error(e)}


if __name__ == "__main__":
    import json
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    print(json.dumps(check_urlscan(url), indent=2))
