"""
Stage 8: Risk score
Aggregates signals from all scanning engines into a calibrated 0-100 score,
verdict, and categorized evidence.
"""


def compute_risk_score(
    heuristics_result,
    tls_result,
    whois_result,
    vt_result,
    urlscan_result,
    redirect_result=None,
    content_result=None,
    dns_result=None,
    parsed=None,
    urlhaus_result=None,
    safe_browsing_result=None,
    phishing_result=None,
    typosquatting_result=None,
    homoglyph_result=None,
    ct_result=None,
) -> dict:
    score = 0.0
    reasons = []
    notes = []

    # 1. Base heuristics (45% scaled contribution)
    h_score = heuristics_result.get("score", 0) if heuristics_result else 0
    score += h_score * 0.45
    if heuristics_result:
        reasons.extend(heuristics_result.get("flags", []))
        score += heuristics_result.get("direct_score", 0)

    # 2. Redirect Analysis (deep hop security: protocol downgrade, open redirect)
    if redirect_result and isinstance(redirect_result, dict):
        analysis = redirect_result.get("analysis", {})
        if analysis:
            if analysis.get("protocol_downgrade"):
                if "Protocol downgrade detected: redirected from HTTPS to insecure plaintext HTTP" not in reasons:
                    reasons.append("Protocol downgrade detected: redirected from HTTPS to insecure plaintext HTTP")
                    score += 25
            if analysis.get("open_redirect_suspect"):
                param = analysis.get("open_redirect_param") or "query"
                reasons.append(f"Suspected open redirect parameter '{param}' used to bounce traffic")
                score += 25
            if analysis.get("shorteners_used") and len(analysis["shorteners_used"]) > 1:
                reasons.append(f"Nested URL shorteners ({' -> '.join(analysis['shorteners_used'])})")
                score += 15

    # 3. Homoglyph & Punycode detection
    if homoglyph_result and isinstance(homoglyph_result, dict) and homoglyph_result.get("has_homoglyphs"):
        score += homoglyph_result.get("risk_score", 25)
        for flag in homoglyph_result.get("flags", []):
            if flag not in reasons:
                reasons.append(flag)

    # 4. Typosquatting detection
    if typosquatting_result and isinstance(typosquatting_result, dict) and typosquatting_result.get("is_typosquat"):
        score += typosquatting_result.get("risk_score", 25)
        for flag in typosquatting_result.get("flags", []):
            if flag not in reasons:
                reasons.append(flag)

    # 5. Phishing detection engine
    if phishing_result and isinstance(phishing_result, dict) and phishing_result.get("is_phishing"):
        p_score = phishing_result.get("phishing_score", 0)
        score += p_score * 0.40
        for flag in phishing_result.get("flags", []):
            if flag not in reasons:
                reasons.append(flag)
        if phishing_result.get("phishing_kit_detected"):
            score = max(score, 75.0)

    # 6. Page-content findings
    if isinstance(content_result, dict) and content_result.get("flags"):
        score += content_result.get("score", 0)
        for flag in content_result["flags"]:
            if flag not in reasons:
                reasons.append(flag)

    # 7. Malformed / obfuscated host
    if parsed is not None and not parsed.get("hostname"):
        reasons.append("Malformed URL: no valid host (nothing after the '@')")
        score = max(score, 40.0)

    # Severe structural heuristic flags guarantee at least Medium Risk (45)
    if h_score >= 60:
        score = max(score, 45.0)

    # 8. TLS health
    if tls_result and not tls_result.get("valid"):
        if tls_result.get("reachable") is False:
            reasons.append("Could not reach host to check TLS (network/DNS issue)")
        else:
            tls_penalties = 0
            if tls_result.get("self_signed"):
                tls_penalties += 15
                reasons.append("Self-signed TLS certificate (untrusted authority)")
            if tls_result.get("expired") or (
                tls_result.get("days_remaining") is not None and tls_result["days_remaining"] < 0
            ):
                tls_penalties += 15
                days_ago = abs(tls_result["days_remaining"]) if tls_result.get("days_remaining") is not None else ""
                day_str = f" ({days_ago} days ago)" if days_ago else ""
                reasons.append(f"TLS certificate has expired{day_str}")
            if not tls_penalties:
                tls_penalties += 15
                reasons.append("No valid TLS certificate (failed validation)")
            score += tls_penalties
    elif tls_result:
        days_remaining = tls_result.get("days_remaining")
        if days_remaining is not None and days_remaining < 7:
            score += 5
            reasons.append(f"TLS certificate expires very soon ({days_remaining} days remaining)")

    # 9. Certificate Transparency
    if ct_result and isinstance(ct_result, dict) and ct_result.get("risk_score", 0) > 0:
        score += ct_result.get("risk_score", 0)
        for flag in ct_result.get("flags", []):
            if flag not in reasons:
                reasons.append(flag)

    # 10. Domain age (WHOIS)
    if whois_result:
        age_days = whois_result.get("age_days")
        if age_days is not None:
            if age_days < 30:
                score += 20
                reasons.append(f"Domain registered very recently ({age_days} days ago)")
            elif age_days < 180:
                score += 10
                reasons.append(f"Domain is fairly new ({age_days} days ago)")

    # 11. URLhaus (abuse.ch) — High-fidelity threat feed
    if urlhaus_result and isinstance(urlhaus_result, dict):
        if urlhaus_result.get("listed"):
            threat = urlhaus_result.get("threat") or "malware_download"
            tags = ", ".join(urlhaus_result.get("tags") or [])
            tag_str = f" [{tags}]" if tags else ""
            reasons.append(f"URLhaus: Active malware distribution link ({threat}){tag_str}")
            score = max(score + 50, 80.0)
        elif urlhaus_result.get("host_listed"):
            count = urlhaus_result.get("host_url_count", 0)
            reasons.append(f"URLhaus: Host has historical record of hosting malware ({count} payloads)")
            score += 25

    # 12. Google Safe Browsing — High-fidelity blacklist
    if safe_browsing_result and isinstance(safe_browsing_result, dict) and safe_browsing_result.get("matched"):
        threat_desc = ", ".join(safe_browsing_result.get("threat_descriptions") or safe_browsing_result.get("threat_types") or [])
        reasons.append(f"Google Safe Browsing: Blacklisted threat ({threat_desc})")
        score = max(score + 50, 85.0)

    # 13. VirusTotal
    vt_malicious = vt_result.get("malicious", 0) if isinstance(vt_result, dict) else 0
    vt_suspicious = vt_result.get("suspicious", 0) if isinstance(vt_result, dict) else 0
    vt_total = (
        vt_malicious
        + vt_suspicious
        + vt_result.get("harmless", 0)
        + vt_result.get("undetected", 0)
        if isinstance(vt_result, dict)
        else 0
    )
    if vt_malicious:
        score += min(vt_malicious * 5, 30)
        if vt_total and vt_malicious == 1 and vt_total >= 20:
            reasons.append(
                f"VirusTotal: 1/{vt_total} engines flagged this as malicious "
                f"(a single hit out of many is often a false positive — worth a second look, not a verdict)"
            )
        elif vt_total:
            reasons.append(f"VirusTotal: {vt_malicious}/{vt_total} engines flagged this as malicious")
        else:
            reasons.append(f"VirusTotal: {vt_malicious} engines flagged this as malicious")
    if vt_suspicious:
        score += min(vt_suspicious * 2, 10)
        if vt_total:
            reasons.append(f"VirusTotal: {vt_suspicious}/{vt_total} engines flagged this as suspicious")
        else:
            reasons.append(f"VirusTotal: {vt_suspicious} engines flagged this as suspicious")

    # 14. urlscan.io
    if isinstance(urlscan_result, dict) and urlscan_result.get("malicious"):
        score += 15
        reasons.append("urlscan.io flagged this URL as malicious")

    score = max(0, min(100, round(score)))

    if score >= 70:
        verdict = "High Risk"
    elif score >= 40:
        verdict = "Medium Risk"
    elif score >= 15:
        verdict = "Low Risk"
    else:
        verdict = "No Known Threats"

    # Coverage gaps
    pending = ("submitted", "pending", "rate_limited")
    if isinstance(vt_result, dict) and (vt_result.get("status") in pending or vt_result.get("error")):
        notes.append("VirusTotal returned no verdict, so its result is missing from this score")
    if isinstance(urlscan_result, dict) and not urlscan_result.get("skipped") and (
        urlscan_result.get("status") in pending or urlscan_result.get("error")
    ):
        notes.append("urlscan.io returned no verdict yet, so its result is missing from this score")
    if isinstance(safe_browsing_result, dict) and safe_browsing_result.get("skipped"):
        notes.append("Google Safe Browsing check was skipped (SAFE_BROWSING_API_KEY not set)")
    if isinstance(content_result, dict) and content_result.get("error"):
        notes.append(content_result["error"])

    unresolved = bool(dns_result) and not dns_result.get("A") and not dns_result.get("AAAA")
    if unresolved and score < 40:
        verdict = "Inconclusive"
        notes.append(
            "Host does not resolve (unregistered, taken down or parked), so the page could not be "
            "analyzed. A low score here is NOT a safety signal"
        )

    if verdict in ("No Known Threats", "Low Risk"):
        notes.append(
            "'No known threats' means nothing was detected, not that the page is safe: brand-new "
            "phishing pages are usually unlisted on threat feeds for hours or days"
        )

    return {"score": score, "verdict": verdict, "reasons": reasons, "notes": notes}
