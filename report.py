"""
Terminal report formatter.
Takes the pipeline's result dict and renders a comprehensive, colorized report
directly to stdout — no browser, no server.
"""

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
GRAY = "\033[90m"
PURPLE = "\033[95m"

VERDICT_COLORS = {
    "High Risk": RED,
    "Medium Risk": ORANGE,
    "Low Risk": YELLOW,
    "No Known Threats": GREEN,
    "Likely Safe": GREEN,
    "Inconclusive": GRAY,
}

WIDTH = 70


def _rule(char="─"):
    return GRAY + char * WIDTH + RESET


def _header(title):
    return f"\n{BOLD}{CYAN}{title}{RESET}\n{_rule()}"


def _kv(label, value, width=22):
    return f"  {GRAY}{label:<{width}}{RESET} {value}"


def format_report(result: dict) -> str:
    lines = []
    parsed = result["parsed"]
    risk = result["risk"]
    dns_res = result.get("dns", {})
    tls_res = result.get("tls", {})
    whois_res = result.get("whois", {})
    heur = result.get("heuristics", {})
    vt = result.get("virustotal", {})
    us = result.get("urlscan", {})
    redirect = result.get("redirect", {})
    homo = result.get("homoglyph", {})
    typo = result.get("typosquatting", {})
    ct = result.get("cert_transparency", {})
    phish = result.get("phishing", {})
    uh = result.get("urlhaus", {})
    sb = result.get("safe_browsing", {})

    color = VERDICT_COLORS.get(risk["verdict"], RESET)

    lines.append(_rule("═"))
    lines.append(f"{BOLD}  URL SCANNER v2 REPORT{RESET}")
    lines.append(_rule("═"))
    lines.append(f"  Input:  {BOLD}{result.get('input_url', parsed['original_url'])}{RESET}")
    if redirect.get("was_redirected"):
        lines.append(f"  Real destination: {BOLD}{YELLOW}{parsed['original_url']}{RESET}  {GRAY}(unmasked){RESET}")
    else:
        lines.append(f"  Target: {BOLD}{parsed['original_url']}{RESET}")

    # 1. REDIRECT ANALYSIS
    if not redirect.get("skipped"):
        lines.append(_header("REDIRECT ANALYSIS"))
        if redirect.get("error"):
            lines.append(f"  {RED}{redirect['error']}{RESET}")
        elif redirect.get("was_redirected"):
            analysis = redirect.get("analysis", {})
            lines.append(_kv("Total Hops", str(redirect["redirect_count"])))
            lines.append(_kv("Cross-domain", "Yes" if redirect.get("cross_domain") else "No"))
            if analysis.get("protocol_downgrade"):
                lines.append(_kv("Protocol downgrade", f"{RED}Yes (HTTPS -> HTTP){RESET}"))
            if analysis.get("open_redirect_suspect"):
                param = analysis.get("open_redirect_param") or "query"
                lines.append(_kv("Open redirect", f"{RED}Suspected via '?{param}='{RESET}"))
            if analysis.get("shorteners_used"):
                lines.append(_kv("Shorteners in chain", ", ".join(analysis["shorteners_used"])))

            lines.append(f"\n  {BOLD}Hop Chain:{RESET}")
            hops = analysis.get("hops") or []
            if hops:
                for h in hops:
                    arrow = "  " if h.get("hop") == 0 else f"  {GRAY}└─>{RESET} "
                    st_code = f" [{h['type']}]" if h.get("type") else ""
                    lines.append(f"{arrow}{h.get('url')}{GRAY}{st_code}{RESET}")
            else:
                for i, hop in enumerate(redirect.get("redirect_chain", [])):
                    arrow = "  " if i == 0 else f"  {GRAY}└─>{RESET} "
                    lines.append(f"{arrow}{hop}")
        else:
            lines.append(f"  {GREEN}No redirects — direct destination link.{RESET}")

    # 2. RISK SCORE
    lines.append(_header("RISK SCORE"))
    bar_filled = int(risk["score"] / 100 * 40)
    bar = color + "█" * bar_filled + GRAY + "░" * (40 - bar_filled) + RESET
    lines.append(f"  {bar}  {BOLD}{color}{risk['score']}/100{RESET}")
    lines.append(f"  Verdict: {BOLD}{color}{risk['verdict']}{RESET}")

    if risk["reasons"]:
        lines.append(f"\n  {BOLD}Key Findings & Red Flags:{RESET}")
        for reason in risk["reasons"]:
            lines.append(f"    {color}●{RESET} {reason}")
    else:
        lines.append(f"\n  {GREEN}No red flags detected.{RESET}")

    if risk.get("notes"):
        lines.append(f"\n  {BOLD}Notes & Coverage:{RESET}")
        for note in risk["notes"]:
            lines.append(f"    {GRAY}○{RESET} {note}")

    # 3. THREAT INTELLIGENCE: URLHAUS & SAFE BROWSING
    lines.append(_header("THREAT INTELLIGENCE (FEEDS & BLACKLISTS)"))
    # URLhaus
    if uh:
        if uh.get("listed"):
            lines.append(_kv("URLhaus", f"{RED}LISTED MALICIOUS ({uh.get('threat')}){RESET}"))
            if uh.get("tags"):
                lines.append(_kv("Malware tags", ", ".join(uh["tags"])))
            if uh.get("url_status"):
                lines.append(_kv("Payload status", uh["url_status"]))
        elif uh.get("host_listed"):
            lines.append(_kv("URLhaus", f"{ORANGE}Host has {uh.get('host_url_count')} malware records{RESET}"))
        elif uh.get("error"):
            lines.append(_kv("URLhaus", f"{GRAY}{uh['error']}{RESET}"))
        else:
            lines.append(_kv("URLhaus", f"{GREEN}Clean (not listed){RESET}"))

    # Safe Browsing
    if sb:
        if sb.get("matched"):
            types = ", ".join(sb.get("threat_descriptions") or sb.get("threat_types") or [])
            lines.append(_kv("Safe Browsing", f"{RED}BLACKLISTED ({types}){RESET}"))
        elif sb.get("skipped"):
            lines.append(_kv("Safe Browsing", f"{GRAY}Not configured (set SAFE_BROWSING_API_KEY){RESET}"))
        elif sb.get("error"):
            lines.append(_kv("Safe Browsing", f"{GRAY}{sb['error']}{RESET}"))
        else:
            lines.append(_kv("Safe Browsing", f"{GREEN}Clean (no threat matches){RESET}"))

    # VirusTotal
    if vt:
        if vt.get("error"):
            lines.append(_kv("VirusTotal", f"{GRAY}{vt['error']}{RESET}"))
        elif vt.get("status") in ("submitted", "pending", "rate_limited"):
            lines.append(_kv("VirusTotal", f"{YELLOW}{vt.get('message') or vt.get('error')}{RESET}"))
        else:
            mal = vt.get("malicious", 0)
            mal_color = RED if mal else GREEN
            lines.append(_kv("VirusTotal", f"{mal_color}{mal} malicious{RESET} / {vt.get('suspicious', 0)} suspicious"))

    # 4. PHISHING & BRAND INTEGRITY
    lines.append(_header("PHISHING & BRAND INTEGRITY"))
    if phish:
        if phish.get("is_phishing"):
            conf_color = RED if phish.get("confidence") in ("High", "Critical") else ORANGE
            lines.append(_kv("Phishing verdict", f"{conf_color}YES ({phish.get('confidence')} Confidence){RESET}"))
            if phish.get("targeted_brand"):
                lines.append(_kv("Targeted brand", f"{PURPLE}{phish['targeted_brand'].upper()}{RESET}"))
            if phish.get("phishing_kit_detected"):
                lines.append(_kv("Phishing kit", f"{RED}Active phishing kit signature detected{RESET}"))
            if phish.get("exfiltration_endpoints"):
                lines.append(_kv("Exfiltration target", phish["exfiltration_endpoints"][0]))
        else:
            lines.append(_kv("Phishing detector", f"{GREEN}No phishing kits or credential drops detected{RESET}"))

    # Typosquatting
    if typo:
        if typo.get("is_typosquat"):
            lines.append(_kv("Typosquatting", f"{RED}YES — mimics {typo.get('matched_brand')} ({typo.get('technique')}){RESET}"))
            lines.append(_kv("Official domain", typo.get("official_domain") or "—"))
            lines.append(_kv("Similarity score", f"{int(typo.get('similarity_score', 0) * 100)}%"))
        else:
            lines.append(_kv("Typosquatting", f"{GREEN}No typosquatting detected{RESET}"))

    # Homoglyphs
    if homo:
        if homo.get("has_homoglyphs"):
            detail = "Mixed script IDN spoof" if homo.get("is_mixed_script") else "Confusable Unicode characters"
            lines.append(_kv("Homoglyph attack", f"{RED}YES ({detail}){RESET}"))
            if homo.get("is_punycode"):
                lines.append(_kv("Punycode domain", homo.get("unicode_domain")))
            if homo.get("target_impersonated"):
                lines.append(_kv("Spoofed brand", f"{PURPLE}{homo['target_impersonated'].upper()}{RESET}"))
            if homo.get("confusable_chars"):
                c_samples = [f"'{c['char']}' -> '{c['lookalike']}' ({c['script']})" for c in homo["confusable_chars"][:2]]
                lines.append(_kv("Confusables", ", ".join(c_samples)))
        else:
            lines.append(_kv("Homoglyphs", f"{GREEN}Clean (standard ASCII){RESET}"))

    # 5. CERTIFICATE TRANSPARENCY & TLS
    lines.append(_header("CERTIFICATE TRANSPARENCY & TLS"))
    if tls_res.get("valid"):
        issuer = tls_res["issuer"].get("organizationName") or tls_res["issuer"].get("commonName", "—")
        lines.append(_kv("TLS Issuer", issuer))
        lines.append(_kv("TLS Expires", f"{tls_res['not_after']} ({tls_res['days_remaining']} days)"))
        lines.append(_kv("Self-signed", "Yes" if tls_res["self_signed"] else "No"))
    elif tls_res.get("reachable") is False:
        lines.append(f"  {YELLOW}Could not reach host to check TLS: {tls_res.get('error')}{RESET}")
    else:
        lines.append(f"  {RED}TLS Error: {tls_res.get('error', 'invalid')}{RESET}")

    if ct and not ct.get("error"):
        lines.append(_kv("CT Total Certs", str(ct.get("total_certs", 0))))
        if ct.get("first_seen"):
            lines.append(_kv("CT First Logged", f"{ct['first_seen'][:10]} ({ct.get('history_days', '—')} days of history)"))
        if ct.get("recent_certs_7d") is not None and ct["recent_certs_7d"] > 0:
            lines.append(_kv("Recent Certs (7d)", str(ct["recent_certs_7d"])))
        if ct.get("discovered_subdomains"):
            lines.append(_kv("Discovered Subs", f"{len(ct['discovered_subdomains'])} subdomains logged in CT"))
    elif ct and ct.get("error"):
        lines.append(_kv("CT Logs", f"{GRAY}{ct['error']}{RESET}"))

    # 6. PARSED URL & DNS
    lines.append(_header("INFRASTRUCTURE & DNS"))
    lines.append(_kv("Hostname", parsed["hostname"] or "—"))
    lines.append(_kv("Registered domain", parsed["registered_domain"] or "—"))
    for rtype, values in dns_res.items():
        lines.append(_kv(rtype, ", ".join(values) if values else f"{GRAY}—{RESET}"))

    # 7. WHOIS
    lines.append(_header("WHOIS"))
    if whois_res.get("error"):
        lines.append(f"  {GRAY}{whois_res['error']}{RESET}")
    else:
        lines.append(_kv("Registrar", whois_res.get("registrar") or "—"))
        lines.append(_kv("Created", whois_res.get("creation_date") or "—"))
        age = whois_res.get("age_days")
        lines.append(_kv("Domain age", f"{age} days" if age is not None else "—"))

    # 8. PAGE CONTENT
    content = result.get("content", {})
    if not content.get("skipped"):
        lines.append(_header("PAGE CONTENT"))
        if content.get("error"):
            lines.append(f"  {GRAY}{content['error']}{RESET}")
        else:
            lines.append(_kv("Title", content.get("title") or "—"))
            lines.append(_kv("Password field", f"{RED}Yes{RESET}" if content.get("has_password_field") else "No"))
            if content.get("form_actions"):
                lines.append(_kv("Form posts to", content["form_actions"][0]))

    lines.append(_rule("═"))
    return "\n".join(lines)


def format_report_plain(result: dict) -> str:
    """Same report with no ANSI codes, for piping to a file or non-tty output."""
    import re
    ansi_escape = re.compile(r"\033\[[0-9;]*m")
    return ansi_escape.sub("", format_report(result))
