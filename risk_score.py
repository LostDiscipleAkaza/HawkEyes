"""
Stage 8: Risk score
Aggregates every prior stage's signal into a single 0-100 score plus a
human-readable verdict and the list of reasons behind it.
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
) -> dict:
    score = 0.0
    reasons = []
    notes = []  # context that is NOT a risk signal (coverage gaps, caveats)

    # Heuristics contribute 45% weight of their own 0-100 score.
    # Redirect-chain signals (hop count, cross-domain redirects, shorteners)
    # are already folded into heuristics_result by score_heuristics(), so
    # they don't need separate handling here - this avoids double-counting.
    h_score = heuristics_result.get("score", 0)
    score += h_score * 0.45
    reasons.extend(heuristics_result.get("flags", []))

    # Signals strong enough to count at full value instead of being scaled
    # by 45% (anonymous tunnel hosting, brand impersonation).
    score += heuristics_result.get("direct_score", 0)

    # Page-content findings (password form, foreign form action, camera /
    # location prompts, brand in title). These are the strongest evidence
    # against fresh phishing pages whose URL and infrastructure look clean.
    if isinstance(content_result, dict) and content_result.get("flags"):
        score += content_result.get("score", 0)
        reasons.extend(content_result["flags"])

    # A URL with no usable host (e.g. "https://login.example.com@") is
    # malformed or deliberately obfuscated - never treat it as clean.
    if parsed is not None and not parsed.get("hostname"):
        reasons.append("Malformed URL: no valid host (nothing after the '@')")
        score = max(score, 40.0)

    # Severe structural heuristic flags guarantee at least Medium Risk (45)
    # so raw-IP / HTTP / credential-keyword links don't get dismissed as Low Risk
    if h_score >= 60:
        score = max(score, 45.0)

    # TLS health
    if not tls_result.get("valid"):
        if tls_result.get("reachable") is False:
            # Host was unreachable (network/DNS/firewall) - not a security
            # signal about the site itself, so don't penalize the score.
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
    else:
        days_remaining = tls_result.get("days_remaining")
        if days_remaining is not None and days_remaining < 7:
            score += 5
            reasons.append(f"TLS certificate expires very soon ({days_remaining} days remaining)")

    # Domain age
    age_days = whois_result.get("age_days")
    if age_days is not None:
        if age_days < 30:
            score += 20
            reasons.append(f"Domain registered very recently ({age_days} days ago)")
        elif age_days < 180:
            score += 10
            reasons.append(f"Domain is fairly new ({age_days} days ago)")

    # VirusTotal — a single flagged engine out of 60+ is frequently a
    # heuristic false positive (this is common, well-documented behavior
    # on VT), so surface the ratio for context instead of a bare count.
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

    # urlscan.io
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

    # Coverage gaps: say so instead of letting silence read as "safe".
    pending = ("submitted", "pending", "rate_limited")
    if isinstance(vt_result, dict) and (vt_result.get("status") in pending or vt_result.get("error")):
        notes.append("VirusTotal returned no verdict, so its result is missing from this score")
    if isinstance(urlscan_result, dict) and not urlscan_result.get("skipped") and (
        urlscan_result.get("status") in pending or urlscan_result.get("error")
    ):
        notes.append("urlscan.io returned no verdict yet, so its result is missing from this score")
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
            "phishing pages are usually unlisted on VirusTotal for hours or days"
        )

    return {"score": score, "verdict": verdict, "reasons": reasons, "notes": notes}