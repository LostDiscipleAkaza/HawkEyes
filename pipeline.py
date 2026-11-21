"""
Orchestrates the full URL scanner pipeline:

Redirect resolution & analysis (unmask shorteners/cloaking, open redirects, protocol downgrades)
  -> URL parser (on the REAL destination)
  -> Homoglyph & IDN detection (confusables, Punycode, mixed scripts)
  -> Typosquatting detection (Levenshtein, omission, substitution, combosquatting)
  -> DNS lookup (A, AAAA, MX, NS, TXT)
  -> TLS check (handshake, cert validity, self-signed detection)
  -> Certificate Transparency (CT logs via crt.sh, issuance patterns, subdomains)
  -> WHOIS / RDAP (registration age, registrar)
  -> URL heuristics (rules engine)
  -> Page content analysis (forms, camera/location, password fields)
  -> Phishing detection engine (credential harvesting, exfiltration drops, phishing kits)
  -> VirusTotal (multi-engine verdicts)
  -> URLhaus (abuse.ch malware intelligence)
  -> Google Safe Browsing (threat blacklist)
  -> urlscan.io (live sandboxed analysis)
  -> Risk scoring engine (calibrated 0-100 score & verdict)
  -> Threat relationship graph
"""
from url_parser import parse_url
from redirect_resolver import resolve_redirects
from homoglyph import detect_homoglyphs
from typosquatting import detect_typosquatting
from dns_lookup import lookup_dns
from tls_check import check_tls
from cert_transparency import check_certificate_transparency
from whois_lookup import lookup_whois
from heuristics import score_heuristics
from content_check import check_content
from phishing_detector import analyze_phishing
from virustotal import check_virustotal
from urlhaus import check_urlhaus
from safe_browsing import check_safe_browsing
from urlscan import check_urlscan
from risk_score import compute_risk_score
from threat_graph import build_threat_graph


def run_pipeline(
    raw_url: str,
    use_urlscan: bool = False,
    follow_redirects: bool = True,
    vt_max_wait: float = 25.0,
    urlscan_max_wait: float = 30.0,
) -> dict:
    original_parsed = parse_url(raw_url)

    # 1. Redirect resolution & security analysis
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
            "analysis": {
                "hops": [],
                "hop_count": 0,
                "flags": [],
                "risk_score": 0,
            },
        }
        final_url = original_parsed["original_url"]

    # Everything downstream scans the REAL destination
    parsed = parse_url(final_url)
    hostname = parsed["hostname"]
    registered_domain = parsed["registered_domain"]

    # 2. Homoglyph & Typosquatting checks (instant offline analyzers)
    homoglyph_result = detect_homoglyphs(parsed["original_url"])
    typosquatting_result = detect_typosquatting(parsed.get("domain") or hostname, registered_domain=registered_domain)

    # 3. DNS lookup
    dns_result = lookup_dns(hostname, registered_domain=registered_domain)

    # 4. TLS & Certificate Transparency
    tls_result = check_tls(hostname)
    ct_result = check_certificate_transparency(registered_domain) if registered_domain else {"total_certs": 0, "flags": []}

    # 5. WHOIS
    whois_result = lookup_whois(registered_domain)

    # 6. Heuristics
    heuristics_result = score_heuristics(parsed, redirect=redirect_result)

    # 7. Content & Phishing Analysis
    if hostname:
        content_result = check_content(parsed["original_url"])
        phishing_result = analyze_phishing(
            parsed_url=parsed,
            content_result=content_result,
            whois_result=whois_result,
            heuristics_result=heuristics_result,
        )
        vt_result = check_virustotal(parsed["original_url"], max_wait=vt_max_wait)
        urlhaus_result = check_urlhaus(parsed["original_url"], hostname=hostname)
        safe_browsing_result = check_safe_browsing(parsed["original_url"])
        urlscan_result = (
            check_urlscan(parsed["original_url"], max_wait=urlscan_max_wait)
            if use_urlscan
            else {"skipped": True}
        )
    else:
        content_result = {"skipped": True}
        phishing_result = {"is_phishing": False, "flags": []}
        vt_result = {"error": "skipped: URL has no valid host"}
        urlhaus_result = {"listed": False, "error": "skipped: URL has no valid host"}
        safe_browsing_result = {"matched": False, "error": "skipped: URL has no valid host", "skipped": True}
        urlscan_result = {"skipped": True}

    # 8. Composite Risk Score
    risk = compute_risk_score(
        heuristics_result=heuristics_result,
        tls_result=tls_result,
        whois_result=whois_result,
        vt_result=vt_result,
        urlscan_result=urlscan_result,
        redirect_result=redirect_result,
        content_result=content_result,
        dns_result=dns_result,
        parsed=parsed,
        urlhaus_result=urlhaus_result,
        safe_browsing_result=safe_browsing_result,
        phishing_result=phishing_result,
        typosquatting_result=typosquatting_result,
        homoglyph_result=homoglyph_result,
        ct_result=ct_result,
    )

    # 9. Threat Relationship Graph
    scan_output = {
        "input_url": raw_url,
        "redirect": redirect_result,
        "parsed": parsed,
        "homoglyph": homoglyph_result,
        "typosquatting": typosquatting_result,
        "dns": dns_result,
        "tls": tls_result,
        "cert_transparency": ct_result,
        "whois": whois_result,
        "heuristics": heuristics_result,
        "content": content_result,
        "phishing": phishing_result,
        "virustotal": vt_result,
        "urlhaus": urlhaus_result,
        "safe_browsing": safe_browsing_result,
        "urlscan": urlscan_result,
        "risk": risk,
    }

    scan_output["threat_graph"] = build_threat_graph(scan_output)
    return scan_output


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
