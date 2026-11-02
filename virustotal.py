"""
Stage 6: VirusTotal
Checks the URL against VT's aggregated multi-engine verdicts (VT API v3).

VT's scanning is asynchronous: if it has never seen a URL, submitting it
only queues an analysis - the ~70+ AV engines take anywhere from a few
seconds to a couple of minutes to actually finish. So after submitting,
this module polls the analysis endpoint for a short window instead of
just returning "submitted" immediately, which is what made it look like
results "never showed up" - they just hadn't been produced yet.

Requires env var VT_API_KEY (get one free at virustotal.com). Also reads
a .env file in the project folder if present, via python-dotenv - this
avoids the common issue where a key set with `export`/`set` in one
terminal session doesn't carry over to a different shell or tool.
"""
import base64
import os
import time

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed - fall back to real env vars only

VT_BASE = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _format_url_report(attrs: dict) -> dict:
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation"),
        "categories": attrs.get("categories", {}),
    }


def check_virustotal(url: str, timeout: float = 10.0, max_wait: float = 25.0) -> dict:
    """
    max_wait: how long (seconds) to poll a freshly-submitted URL before
    giving up and reporting it as still processing. Set to 0 to disable
    polling and return immediately after submission.

    VirusTotal free API has a strict 4 requests/minute limit (~15s between calls).
    Polling is paced to respect this limit and avoid HTTP 429 errors.
    """
    api_key = os.environ.get("VT_API_KEY", "")
    if not api_key:
        return {"error": "VT_API_KEY not configured"}

    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(f"{VT_BASE}/urls/{_url_id(url)}", headers=headers, timeout=timeout)

        if resp.status_code == 404:
            submit = requests.post(
                f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=timeout
            )
            if submit.status_code == 429:
                return {
                    "status": "rate_limited",
                    "error": "VirusTotal free-tier rate limit reached (4 req/min). Scan could not be queued; try again in ~60s.",
                }
            submit.raise_for_status()
            analysis_id = submit.json().get("data", {}).get("id")

            if max_wait <= 0 or not analysis_id:
                return {
                    "status": "submitted",
                    "message": "URL submitted for analysis; check back shortly",
                }

            # Poll the analysis endpoint with rate-limit-aware pacing.
            # VT scans take at least 10-15s to finish across ~70 engines.
            # Free API keys allow 4 requests/min, so we space polls out by ~15s.
            waited = 0.0
            first_delay = min(12.0, max_wait)
            time.sleep(first_delay)
            waited += first_delay

            poll_interval = 15.0
            while waited <= max_wait:
                analysis = requests.get(
                    f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=timeout
                )
                if analysis.status_code == 429:
                    return {
                        "status": "rate_limited",
                        "message": f"VirusTotal free-tier rate limit reached (4 req/min). Analysis queued under ID {analysis_id[:8]}...; check back in ~60s.",
                    }
                analysis.raise_for_status()
                analysis_data = analysis.json().get("data", {})
                if analysis_data.get("attributes", {}).get("status") == "completed":
                    # Re-fetch the full URL report now that analysis is done
                    final = requests.get(
                        f"{VT_BASE}/urls/{_url_id(url)}", headers=headers, timeout=timeout
                    )
                    if final.status_code == 429:
                        # Fallback to stats in analysis object itself if available
                        stats = analysis_data.get("attributes", {}).get("stats", {})
                        if stats:
                            return {
                                "malicious": stats.get("malicious", 0),
                                "suspicious": stats.get("suspicious", 0),
                                "harmless": stats.get("harmless", 0),
                                "undetected": stats.get("undetected", 0),
                                "reputation": 0,
                                "categories": {},
                            }
                    final.raise_for_status()
                    return _format_url_report(final.json()["data"]["attributes"])

                if waited + poll_interval > max_wait:
                    break
                time.sleep(poll_interval)
                waited += poll_interval

            return {
                "status": "pending",
                "message": f"Still analyzing after {int(waited)}s; VT scans can take 30-60s for brand-new URLs — use --full-scan or check again shortly",
            }

        if resp.status_code == 429:
            return {
                "status": "rate_limited",
                "error": "VirusTotal free-tier rate limit reached (4 requests/minute). Please wait ~60s before rescanning.",
            }
        resp.raise_for_status()
        return _format_url_report(resp.json()["data"]["attributes"])
    except requests.HTTPError as e:
        if e.response is not None:
            if e.response.status_code == 401:
                return {"error": "VT_API_KEY was rejected (401 Unauthorized) — check the key is correct and active"}
            if e.response.status_code == 429:
                return {
                    "status": "rate_limited",
                    "error": "VirusTotal free-tier rate limit reached (4 requests/minute). Please wait ~60s before rescanning.",
                }
        return {"error": str(e)}
    except requests.RequestException as e:
        return {"error": str(e)}


if __name__ == "__main__":
    import json
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    print(json.dumps(check_virustotal(url), indent=2))
