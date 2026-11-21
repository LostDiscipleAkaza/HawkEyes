"""
Stage 5: URL heuristics
A lightweight rules engine that flags structural red flags in the URL
itself, with no external calls. Fast, offline, and catches a lot of
low-effort phishing on its own.
"""
import re

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq",
    "work", "click", "link", "country", "kim", "loan", "men", "review",
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "lnkd.in", "linktr.ee", "cutt.ly", "shorturl.at", "t.ly", "rb.gy", "bitly.com",
}

SENSITIVE_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "banking",
    "confirm", "password", "signin", "wallet", "unlock",
]

# Anonymous tunnel / throwaway-hosting services. Anyone can create a
# subdomain in seconds, so the PARENT domain's age, TLS cert and clean
# VirusTotal record say nothing about the page behind it. Phishing kits
# (CamPhish, zphisher, evilginx demos...) are routinely served this way.
TUNNEL_DOMAINS = {
    "trycloudflare.com", "ngrok.io", "ngrok.app", "ngrok.dev", "ngrok-free.app",
    "ngrok-free.dev", "loca.lt", "localtunnel.me", "serveo.net", "serveousercontent.com",
    "localhost.run", "lhr.life", "pagekite.me", "tunnelto.dev", "telebit.io",
    "playit.gg", "portmap.io", "pinggy.link", "pinggy.io",
}
# Free hosting platforms: legitimate in general, but heavily abused.
FREE_HOSTING_DOMAINS = {
    "workers.dev", "pages.dev", "github.io", "herokuapp.com", "vercel.app", "netlify.app",
    "glitch.me", "web.app", "firebaseapp.com", "blogspot.com", "weebly.com",
    "000webhostapp.com", "onrender.com", "repl.co", "replit.dev", "duckdns.org",
    "wixsite.com", "mystrikingly.com", "godaddysites.com",
}

# brand -> registered-domain labels that genuinely belong to that brand
BRANDS = {
    "instagram": {"instagram", "cdninstagram"},
    "facebook": {"facebook", "fb", "fbcdn", "messenger", "meta"},
    "whatsapp": {"whatsapp"},
    "google": {"google", "gstatic", "googleusercontent", "googleapis", "gmail", "goo", "youtube", "withgoogle"},
    "youtube": {"youtube", "youtu", "ytimg"},
    "paypal": {"paypal", "paypalobjects"},
    "amazon": {"amazon", "amazonaws", "amazonpay", "a2z"},
    "microsoft": {"microsoft", "live", "office", "msn", "microsoftonline", "outlook", "windows", "azure", "bing", "onedrive", "sharepoint", "office365"},
    "netflix": {"netflix", "nflxext"},
    "twitter": {"twitter", "x", "twimg"},
    "linkedin": {"linkedin", "licdn", "lnkd"},
    "dropbox": {"dropbox"},
    "github": {"github", "githubusercontent", "githubassets"},
    "binance": {"binance"},
    "coinbase": {"coinbase"},
    "metamask": {"metamask"},
    "spotify": {"spotify", "scdn"},
    "snapchat": {"snapchat", "snap"},
    "discord": {"discord", "discordapp"},
    "telegram": {"telegram", "t"},
    "paytm": {"paytm"},
    "phonepe": {"phonepe"},
    "flipkart": {"flipkart"},
    "hdfcbank": {"hdfcbank"},
    "icicibank": {"icicibank"},
    "icloud": {"icloud", "apple"},
}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s"})


import tldextract
from difflib import SequenceMatcher


def _is_official_label(label: str) -> bool:
    return any(label in official for official in BRANDS.values())


def brand_impersonation(parsed: dict):
    """Return (brand, kind) if the hostname imitates a known brand it
    doesn't belong to; kind is 'contains' or 'lookalike'. Otherwise None."""
    hostname = (parsed.get("hostname") or "").lower()
    label = (parsed.get("domain") or "").lower()
    if not hostname or not label or _is_official_label(label):
        return None

    for brand in BRANDS:
        if brand in hostname:
            return brand, "contains"

    # Typosquats: compare the main label (and its hyphen-separated pieces),
    # after undoing digit-for-letter swaps like paypa1 -> paypal.
    candidates = {label, *label.split("-")}
    for cand in candidates:
        norm = cand.translate(_HOMOGLYPHS)
        for brand in BRANDS:
            if len(brand) < 6 or len(norm) < 5 or cand == brand:
                continue
            if norm == brand or SequenceMatcher(None, norm, brand).ratio() >= 0.8:
                return brand, "lookalike"
    return None


def find_brand_in_text(text: str, page_label: str):
    """Brand named in free text (e.g. a page <title>) that the page's own
    domain label doesn't belong to."""
    if not text or not page_label or _is_official_label(page_label):
        return None
    lowered = text.lower()
    for brand in BRANDS:
        if brand in lowered:
            return brand
    return None


def _matches_domain_set(hostname: str, domains: set):
    for d in domains:
        if hostname == d or hostname.endswith("." + d):
            return d
    return None


def _is_ip_address(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or ""))


_tld_extractor = tldextract.TLDExtract(suffix_list_urls=None)


def _domain(url_str: str) -> str:
    if not url_str:
        return ""
    ext = _tld_extractor(url_str)
    return (getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or "").lower()


def score_heuristics(parsed: dict, redirect: dict = None) -> dict:
    flags = []
    score = 0
    direct = 0  # points applied straight to the final risk score (not scaled down)

    hostname = parsed.get("hostname") or ""
    full_url = parsed.get("original_url") or ""
    subdomain = parsed.get("subdomain") or ""
    suffix = (parsed.get("suffix") or "").split(".")[-1]
    registered_domain = parsed.get("registered_domain") or ""

    is_raw_ip = _is_ip_address(hostname)
    if is_raw_ip:
        flags.append("Hostname is a raw IP address")
        score += 25

    if "@" in full_url:
        flags.append('URL contains "@" (classic redirect / masking trick)')
        score += 20

    sub_count = len([s for s in subdomain.split(".") if s])
    if sub_count >= 3:
        flags.append(f"Excessive subdomains ({sub_count})")
        score += 15

    if hostname.count("-") >= 3:
        flags.append("Hostname contains many hyphens")
        score += 10

    if suffix in SUSPICIOUS_TLDS:
        flags.append(f"Suspicious TLD: .{suffix}")
        score += 15

    tunnel = _matches_domain_set(hostname.lower(), TUNNEL_DOMAINS)
    if tunnel:
        flags.append(
            f"Hosted on a free anonymous tunnel service ({tunnel}): anyone can create a throwaway "
            f"subdomain, so the provider's domain age and clean reputation say nothing about this page"
        )
        direct += 30
    else:
        free_host = _matches_domain_set(hostname.lower(), FREE_HOSTING_DOMAINS)
        if free_host:
            flags.append(f"Hosted on a free/shared hosting platform ({free_host}), often abused for phishing")
            direct += 10

    imp = brand_impersonation(parsed)
    if imp:
        brand, kind = imp
        if kind == "contains":
            flags.append(f"Hostname contains the brand name '{brand}' but is not {brand}'s domain")
        else:
            flags.append(f"Domain '{parsed.get('domain')}' looks like a typo/lookalike of '{brand}'")
        direct += 25

    # Check whether the resolved destination or any original link in the
    # redirect chain used a known shortener (preserves the signal after unmasking).
    used_shortener = registered_domain in KNOWN_SHORTENERS
    shortener_domain = registered_domain if used_shortener else None

    if not used_shortener and redirect:
        orig_url = redirect.get("original_url") or ""
        orig_domain = _domain(orig_url)
        if orig_domain in KNOWN_SHORTENERS:
            used_shortener = True
            shortener_domain = orig_domain
        else:
            for hop in redirect.get("redirect_chain", []):
                hop_domain = _domain(hop)
                if hop_domain in KNOWN_SHORTENERS:
                    used_shortener = True
                    shortener_domain = hop_domain
                    break

    if used_shortener:
        if redirect and redirect.get("was_redirected") and shortener_domain != registered_domain:
            flags.append(f"Original link used a known URL shortener ({shortener_domain}) to conceal destination")
        else:
            flags.append("Known URL shortener (destination is hidden)")
        score += 10

    if len(full_url) > 100:
        flags.append("Unusually long URL")
        score += 10

    is_plain_http = parsed.get("scheme") == "http"
    if is_plain_http:
        flags.append("No HTTPS (plaintext HTTP)")
        score += 10

    # Match complete keyword tokens (\b) rather than arbitrary substrings
    # (prevents false matches on words like 'accountant' or 'cupdates')
    lowered = full_url.lower()
    hit_keywords = [k for k in SENSITIVE_KEYWORDS if re.search(rf"\b{re.escape(k)}\b", lowered)]
    if hit_keywords:
        flags.append(f"Contains phishing-style keywords: {', '.join(hit_keywords)}")
        score += 15

    # Compound indicator: raw IP with plaintext HTTP and login/password keywords
    if is_raw_ip and is_plain_http and hit_keywords:
        flags.append("Dangerous combination: raw IP address hosting plaintext HTTP with credential keywords")
        score += 25

    if redirect:
        if redirect.get("error"):
            flags.append(f"Redirect resolution failed: {redirect['error']}")
        else:
            hop_count = redirect.get("redirect_count", 0)
            if hop_count >= 4:
                flags.append(f"Long redirect chain ({hop_count} hops) — common cloaking technique")
                score += 15
            elif hop_count >= 1:
                flags.append(f"URL redirects {hop_count} time(s) before landing")
                score += 5

            if redirect.get("cross_domain"):
                flags.append(
                    f"Redirects to a different domain than shown "
                    f"({redirect['original_url']} -> {redirect['final_url']})"
                )
                score += 10

    return {"score": min(score, 100), "flags": flags, "direct_score": direct}


if __name__ == "__main__":
    import json
    from url_parser import parse_url

    test_url = "http://secure-login.paypal.verify-account.xyz.top/reset@evil.com"
    print(json.dumps(score_heuristics(parse_url(test_url)), indent=2))