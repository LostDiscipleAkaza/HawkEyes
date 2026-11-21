"""
Stage 6.5: URLhaus (abuse.ch)
Queries the abuse.ch URLhaus threat intelligence database for known malware
distribution URLs and malicious hosts.

URLhaus is a community-driven threat feed tracking malware sites. If a URL
or host is listed here, it is an active or historical malware distribution site.
No API key is required for basic queries, but URLHAUS_API_KEY is supported if set.
"""
import os
import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_API_HOST = "https://urlhaus-api.abuse.ch/v1/host/"

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "application/json",
}


def _clean_error(e: Exception) -> str:
    msg = str(e)
    if isinstance(e, requests.exceptions.ConnectionError):
        if "NameResolutionError" in msg or "Failed to resolve" in msg:
            return "Could not resolve URLhaus API server (DNS/network unavailable)"
        if "RemoteDisconnected" in msg or "Connection aborted" in msg:
            return "URLhaus server closed the connection without responding"
        if "Connection refused" in msg:
            return "Connection to URLhaus server refused"
    if isinstance(e, requests.exceptions.Timeout):
        return "Connection to URLhaus timed out"
    return msg


def check_urlhaus(url: str, hostname: str = None, timeout: float = 6.0) -> dict:
    """
    Queries URLhaus API first for the full URL, and if not found, checks whether
    the host has known malicious URLs associated with it.

    Returns:
        listed: bool (True if URL or host is listed)
        query_status: "ok", "no_results", or error status
        url_status: "online", "offline", or None
        threat: threat classification (e.g. "malware_download")
        tags: list of malware tags (e.g. ["elf", "mozi", "exe", "redline"])
        reporter: threat reporter handle
        date_added: timestamp when added
        host_listed: bool (True if host has history in URLhaus)
        host_url_count: number of malicious URLs on this host
        error: error string or None
    """
    if not url:
        return {"listed": False, "error": "No URL provided", "tags": []}

    api_key = os.environ.get("URLHAUS_API_KEY", "").strip()
    headers = dict(DEFAULT_HEADERS)
    if api_key:
        headers["Auth-KEY"] = api_key

    result = {
        "listed": False,
        "query_status": "no_results",
        "url_status": None,
        "threat": None,
        "tags": [],
        "reporter": None,
        "date_added": None,
        "host_listed": False,
        "host_url_count": 0,
        "error": None,
    }

    # 1. Query exact URL
    try:
        resp = requests.post(
            URLHAUS_API_URL,
            data={"url": url},
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            status = data.get("query_status")
            result["query_status"] = status
            if status == "ok":
                result["listed"] = True
                result["url_status"] = data.get("url_status")
                result["threat"] = data.get("threat")
                result["tags"] = data.get("tags") or []
                result["reporter"] = data.get("reporter")
                result["date_added"] = data.get("date_added")
                return result
        elif resp.status_code == 429:
            result["error"] = "URLhaus rate limit exceeded"
            return result
        elif resp.status_code >= 500:
            result["error"] = f"URLhaus API server error ({resp.status_code})"
            return result
    except requests.RequestException as e:
        result["error"] = f"URLhaus connection failed: {_clean_error(e)}"
        return result

    # 2. Query host if URL wasn't directly listed
    target_host = hostname
    if not target_host and "://" in url:
        from urllib.parse import urlparse
        target_host = urlparse(url).hostname

    if target_host and target_host not in ("localhost", "127.0.0.1"):
        try:
            resp_host = requests.post(
                URLHAUS_API_HOST,
                data={"host": target_host},
                headers=headers,
                timeout=timeout,
            )
            if resp_host.status_code == 200:
                hdata = resp_host.json()
                hstatus = hdata.get("query_status")
                if hstatus == "ok":
                    result["host_listed"] = True
                    urls = hdata.get("urls") or []
                    result["host_url_count"] = hdata.get("url_count") or len(urls)
                    # Pull distinct tags from host history
                    host_tags = set()
                    for u in urls[:10]:
                        for tag in (u.get("tags") or []):
                            host_tags.add(tag)
                    if host_tags and not result["tags"]:
                        result["tags"] = sorted(list(host_tags))
        except requests.RequestException:
            pass  # Host fallback is best-effort

    return result


if __name__ == "__main__":
    import json
    import sys

    test_target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    print(json.dumps(check_urlhaus(test_target), indent=2))
