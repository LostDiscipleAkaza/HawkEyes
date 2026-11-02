"""
Orchestrates the full v1 pipeline:

Redirect resolution (unmask shorteners/cloaking) -> URL parser (on the
REAL destination) -> DNS -> TLS -> WHOIS/RDAP -> heuristics -> VirusTotal
-> page content -> urlscan (optional) -> risk score

Everything from the parser onward runs against the *resolved* final URL,
not whatever wrapper/shortener link was given, so a bit.ly link pointing
at a phishing page gets scored as the phishing page, not as bit.ly.
"""
from url_parser import parse_url
from redirect_resolver import resolve_redirects
from dns_lookup import lookup_dns
from tls_check import check_tls
from whois_lookup import lookup_whois
from heuristics import score_heuristics
from content_check import check_content
from virustotal import check_virustotal
from urlscan import check_urlscan
from risk_score import compute_risk_score


def run_pipeline(
    raw_url: str,
    use_urlscan: bool = False,
    follow_redirects: bool = True,
    vt_max_wait: float = 25.0,
    urlscan_max_wait: float = 30.0,
) -> dict:
    original_parsed = parse_url(raw_url)

    if follow_redirects:
        redirect_result = resolve_redirects(original_parsed["original_url"])
        final_url = redirect_result.get("final_url") or original_parsed["original_url"]
    else:
        redirect_result = {
            "original_url": original_parsed["original_url"],
            "final_url": original_parsed["original_url"],
            "redirect_chain": [original_parsed["original_url"]],
            "redirect_count": 0,
            "was_redirected": False,
            "cross_domain": False,
            "skipped": True,
        }
        final_url = original_parsed["original_url"]

    # Everything downstream scans the REAL destination, not the wrapper link
    parsed = parse_url(final_url)
    hostname = parsed["hostname"]

    dns_result = lookup_dns(hostname, registered_domain=parsed["registered_domain"])
    tls_result = check_tls(hostname)
    whois_result = lookup_whois(parsed["registered_domain"])
    heuristics_result = score_heuristics(parsed, redirect=redirect_result)

    if hostname:
        content_result = check_content(parsed["original_url"])
        vt_result = check_virustotal(parsed["original_url"], max_wait=vt_max_wait)
        urlscan_result = (
            check_urlscan(parsed["original_url"], max_wait=urlscan_max_wait)
            if use_urlscan
            else {"skipped": True}
        )
    else:
        # Malformed URL with no host: don't send garbage to VT/urlscan (they just return 400)
        content_result = {"skipped": True}
        vt_result = {"error": "skipped: URL has no valid host"}
        urlscan_result = {"skipped": True}

    risk = compute_risk_score(
        heuristics_result, tls_result, whois_result, vt_result, urlscan_result, redirect_result,
        content_result=content_result, dns_result=dns_result, parsed=parsed,
    )

    return {
        "input_url": raw_url,
        "redirect": redirect_result,
        "parsed": parsed,
        "dns": dns_result,
        "tls": tls_result,
        "whois": whois_result,
        "heuristics": heuristics_result,
        "content": content_result,
        "virustotal": vt_result,
        "urlscan": urlscan_result,
        "risk": risk,
    }


if __name__ == "__main__":
    import json
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    use_full = "--full-scan" in sys.argv
    use_scan = "--scan" in sys.argv or use_full
    no_redirect = "--no-redirect" in sys.argv
    no_vt_wait = "--no-vt-wait" in sys.argv

    vt_wait = 0.0 if no_vt_wait else (60.0 if use_full else 25.0)
    urlscan_wait = 45.0 if use_full else 30.0

    print(
        json.dumps(
            run_pipeline(
                url,
                use_urlscan=use_scan,
                follow_redirects=not no_redirect,
                vt_max_wait=vt_wait,
                urlscan_max_wait=urlscan_wait,
            ),
            indent=2,
            default=str,
        )
    )