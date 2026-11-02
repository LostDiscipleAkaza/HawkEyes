"""
Terminal report formatter.
Takes the pipeline's result dict and renders a readable, colorized report
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


def _kv(label, value, width=20):
    return f"  {GRAY}{label:<{width}}{RESET} {value}"


def format_report(result: dict) -> str:
    lines = []
    parsed = result["parsed"]
    risk = result["risk"]
    dns_res = result["dns"]
    tls_res = result["tls"]
    whois_res = result["whois"]
    heur = result["heuristics"]
    vt = result["virustotal"]
    us = result["urlscan"]
    redirect = result.get("redirect", {})

    color = VERDICT_COLORS.get(risk["verdict"], RESET)

    lines.append(_rule("═"))
    lines.append(f"{BOLD}  URL SCANNER v1 REPORT{RESET}")
    lines.append(_rule("═"))
    lines.append(f"  Input:  {BOLD}{result.get('input_url', parsed['original_url'])}{RESET}")
    if redirect.get("was_redirected"):
        lines.append(f"  Real destination: {BOLD}{YELLOW}{parsed['original_url']}{RESET}  {GRAY}(unmasked){RESET}")
    else:
        lines.append(f"  Target: {BOLD}{parsed['original_url']}{RESET}")

    if not redirect.get("skipped"):
        lines.append(_header("REDIRECT / LINK UNMASKING"))
        if redirect.get("error"):
            lines.append(f"  {RED}{redirect['error']}{RESET}")
        elif redirect.get("was_redirected"):
            lines.append(_kv("Hops", str(redirect["redirect_count"])))
            lines.append(_kv("Cross-domain", "Yes" if redirect.get("cross_domain") else "No"))
            lines.append(f"\n  {BOLD}Chain:{RESET}")
            for i, hop in enumerate(redirect["redirect_chain"]):
                arrow = "  " if i == 0 else f"  {GRAY}└─>{RESET} "
                lines.append(f"{arrow}{hop}")
        else:
            lines.append(f"  {GREEN}No redirects — this is a direct link.{RESET}")

    lines.append(_header("RISK SCORE"))
    bar_filled = int(risk["score"] / 100 * 40)
    bar = color + "█" * bar_filled + GRAY + "░" * (40 - bar_filled) + RESET
    lines.append(f"  {bar}  {BOLD}{color}{risk['score']}/100{RESET}")
    lines.append(f"  Verdict: {BOLD}{color}{risk['verdict']}{RESET}")

    if risk["reasons"]:
        lines.append(f"\n  {BOLD}Reasons:{RESET}")
        for reason in risk["reasons"]:
            lines.append(f"    {color}●{RESET} {reason}")
    else:
        lines.append(f"\n  {GREEN}No red flags detected.{RESET}")

    if risk.get("notes"):
        lines.append(f"\n  {BOLD}Notes:{RESET}")
        for note in risk["notes"]:
            lines.append(f"    {GRAY}○{RESET} {note}")

    lines.append(_header("PARSED URL"))
    lines.append(_kv("Hostname", parsed["hostname"]))
    lines.append(_kv("Registered domain", parsed["registered_domain"]))
    lines.append(_kv("Scheme", parsed["scheme"]))
    lines.append(_kv("Path", parsed["path"] or "/"))

    lines.append(_header("DNS"))
    for rtype, values in dns_res.items():
        lines.append(_kv(rtype, ", ".join(values) if values else f"{GRAY}—{RESET}"))

    lines.append(_header("TLS CERTIFICATE"))
    if tls_res.get("valid"):
        issuer = tls_res["issuer"].get("organizationName") or tls_res["issuer"].get("commonName", "—")
        lines.append(_kv("Issuer", issuer))
        lines.append(_kv("Expires", f"{tls_res['not_after']}  ({tls_res['days_remaining']} days)"))
        lines.append(_kv("Self-signed", "Yes" if tls_res["self_signed"] else "No"))
    elif tls_res.get("reachable") is False:
        lines.append(f"  {YELLOW}Could not reach host to check TLS: {tls_res.get('error')}{RESET}")
    else:
        lines.append(f"  {RED}{tls_res.get('error', 'invalid')}{RESET}")
        issuer = tls_res.get("issuer", {})
        if issuer:
            iss_str = issuer.get("organizationName") or issuer.get("commonName", "—")
            lines.append(_kv("Issuer", iss_str))
        if tls_res.get("not_after") and tls_res.get("days_remaining") is not None:
            lines.append(_kv("Expires", f"{tls_res['not_after']}  ({tls_res['days_remaining']} days)"))
        if tls_res.get("self_signed"):
            lines.append(_kv("Self-signed", f"{RED}Yes (untrusted){RESET}"))

    lines.append(_header("WHOIS"))
    if whois_res.get("error"):
        lines.append(f"  {GRAY}{whois_res['error']}{RESET}")
    else:
        lines.append(_kv("Registrar", whois_res.get("registrar") or "—"))
        lines.append(_kv("Created", whois_res.get("creation_date") or "—"))
        age = whois_res.get("age_days")
        lines.append(_kv("Domain age", f"{age} days" if age is not None else "—"))

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
            if content.get("note"):
                lines.append(f"  {GRAY}{content['note']}{RESET}")

    lines.append(_header("VIRUSTOTAL"))
    if vt.get("error"):
        lines.append(f"  {GRAY}{vt['error']}{RESET}")
    elif vt.get("status") in ("submitted", "pending", "rate_limited"):
        lines.append(f"  {YELLOW}{vt.get('message') or vt.get('error')}{RESET}")
    else:
        mal = vt.get("malicious", 0)
        mal_color = RED if mal else GREEN
        lines.append(_kv("Malicious", f"{mal_color}{mal}{RESET}"))
        lines.append(_kv("Suspicious", str(vt.get("suspicious", 0))))
        lines.append(_kv("Harmless", str(vt.get("harmless", 0))))
        lines.append(_kv("Reputation", str(vt.get("reputation", "—"))))

    if not us.get("skipped"):
        lines.append(_header("URLSCAN.IO"))
        if us.get("status") in ("pending", "rate_limited", "submitted"):
            lines.append(f"  {YELLOW}{us.get('message') or us.get('error')}{RESET}")
            if us.get("report_url"):
                lines.append(_kv("Report", us["report_url"]))
        elif us.get("error"):
            lines.append(f"  {GRAY}{us['error']}{RESET}")
        else:
            mal_color = RED if us.get("malicious") else GREEN
            lines.append(_kv("Malicious", f"{mal_color}{us.get('malicious')}{RESET}"))
            lines.append(_kv("Score", str(us.get("score", "—"))))
            if us.get("report_url"):
                lines.append(_kv("Report", us["report_url"]))

    lines.append(_rule("═"))
    return "\n".join(lines)


def format_report_plain(result: dict) -> str:
    """Same report with no ANSI codes, for piping to a file or non-tty output."""
    import re

    ansi_escape = re.compile(r"\033\[[0-9;]*m")
    return ansi_escape.sub("", format_report(result))