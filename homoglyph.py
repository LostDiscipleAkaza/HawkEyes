"""
Stage 1.5: Homoglyph & IDN Attack Detection
Detects Internationalized Domain Name (IDN) homograph attacks, confusable
Unicode characters (Cyrillic, Greek, fullwidth, math symbols), zero-width
invisible characters, mixed-script spoofing, and leet-speak substitutions.

Example:
  'gооgle.com' looks identical to 'google.com' in many fonts, but uses
  Cyrillic small letter 'о' (U+043E) instead of Latin 'o' (U+006F).
"""
import unicodedata
from urllib.parse import urlparse

# Confusable character mapping: unicode char -> (ascii lookalike, script name)
CONFUSABLES = {
    # Cyrillic small lookalikes
    "\u0430": ("a", "Cyrillic"),
    "\u0441": ("c", "Cyrillic"),
    "\u0435": ("e", "Cyrillic"),
    "\u043e": ("o", "Cyrillic"),
    "\u0440": ("p", "Cyrillic"),
    "\u0445": ("x", "Cyrillic"),
    "\u0443": ("y", "Cyrillic"),
    "\u0456": ("i", "Cyrillic"),
    "\u0458": ("j", "Cyrillic"),
    "\u0455": ("s", "Cyrillic"),
    "\u0501": ("d", "Cyrillic"),
    "\u051b": ("q", "Cyrillic"),
    "\u051d": ("w", "Cyrillic"),
    # Cyrillic capital lookalikes
    "\u0410": ("A", "Cyrillic"),
    "\u0412": ("B", "Cyrillic"),
    "\u0415": ("E", "Cyrillic"),
    "\u041a": ("K", "Cyrillic"),
    "\u041c": ("M", "Cyrillic"),
    "\u041d": ("H", "Cyrillic"),
    "\u041e": ("O", "Cyrillic"),
    "\u0420": ("P", "Cyrillic"),
    "\u0421": ("C", "Cyrillic"),
    "\u0422": ("T", "Cyrillic"),
    "\u0425": ("X", "Cyrillic"),
    # Greek small lookalikes
    "\u03bf": ("o", "Greek"),
    "\u03bd": ("v", "Greek"),
    "\u03c1": ("p", "Greek"),
    "\u03c4": ("t", "Greek"),
    "\u03c5": ("u", "Greek"),
    "\u03c7": ("x", "Greek"),
    "\u03b9": ("i", "Greek"),
    "\u03ba": ("k", "Greek"),
    # Greek capital lookalikes
    "\u0391": ("A", "Greek"),
    "\u0392": ("B", "Greek"),
    "\u0395": ("E", "Greek"),
    "\u0397": ("H", "Greek"),
    "\u0399": ("I", "Greek"),
    "\u039a": ("K", "Greek"),
    "\u039c": ("M", "Greek"),
    "\u039d": ("N", "Greek"),
    "\u039f": ("O", "Greek"),
    "\u03a1": ("P", "Greek"),
    "\u03a4": ("T", "Greek"),
    "\u03a7": ("X", "Greek"),
    "\u03a5": ("Y", "Greek"),
    "\u0396": ("Z", "Greek"),
    # Cherokee / Other
    "\u13a0": ("D", "Cherokee"),
    "\u13cd": ("R", "Cherokee"),
    "\u13d9": ("b", "Cherokee"),
    # Latin accented/modified often used as spoofing
    "\u0131": ("i", "Latin dotless"),
    "\u0142": ("l", "Latin stroke"),
    "\u0153": ("oe", "Latin ligature"),
}

# Fullwidth ASCII lookalikes (U+FF01 to U+FF5E)
for code in range(0xFF01, 0xFF5F):
    char = chr(code)
    CONFUSABLES[char] = (chr(code - 0xFEE0), "Fullwidth Latin")

# Invisible and zero-width characters
INVISIBLE_CHARS = {
    "\u200b": "Zero Width Space (U+200B)",
    "\u200c": "Zero Width Non-Joiner (U+200C)",
    "\u200d": "Zero Width Joiner (U+200D)",
    "\ufeff": "Byte Order Mark / Zero Width No-Break Space (U+FEFF)",
    "\u00ad": "Soft Hyphen (U+00AD)",
    "\u200e": "Left-To-Right Mark (U+200E)",
    "\u200f": "Right-To-Left Mark (U+200F)",
    "\u202a": "Left-To-Right Embedding (U+202A)",
    "\u202b": "Right-To-Left Embedding (U+202B)",
    "\u202c": "Pop Directional Formatting (U+202C)",
    "\u202d": "Left-To-Right Override (U+202D)",
    "\u202e": "Right-To-Left Override (U+202E)",
}

# High-profile brand domain labels commonly spoofed
HIGH_PROFILE_TARGETS = {
    "google", "paypal", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "twitter", "whatsapp", "telegram", "binance",
    "coinbase", "metamask", "github", "dropbox", "linkedin", "spotify",
    "discord", "chase", "bankofamerica", "wellsfargo", "citibank",
    "icicibank", "hdfcbank", "paytm", "phonepe", "adobe", "walmart",
    "ebay", "target", "steam", "roblox", "epicgames", "yahoo", "outlook",
}


def _get_char_script(ch: str) -> str:
    """Best-effort script detection from Unicode character name."""
    try:
        name = unicodedata.name(ch).upper()
        if "CYRILLIC" in name:
            return "Cyrillic"
        if "GREEK" in name:
            return "Greek"
        if "LATIN" in name:
            return "Latin"
        if "ARABIC" in name:
            return "Arabic"
        if "HEBREW" in name:
            return "Hebrew"
        if "CJK" in name or "HIRAGANA" in name or "KATAKANA" in name:
            return "East Asian"
        if "CHEROKEE" in name:
            return "Cherokee"
        return "Other"
    except ValueError:
        return "Unknown"


def detect_homoglyphs(domain_or_url: str) -> dict:
    """
    Analyzes a domain or URL for homoglyphs, Punycode, mixed scripts,
    and invisible characters.

    Returns:
        has_homoglyphs: bool
        is_punycode: bool
        unicode_domain: decoded Unicode string
        ascii_normalized: string with confusable characters replaced by ASCII
        confusable_chars: list of detected confusable character records
        invisible_chars: list of detected invisible characters
        is_mixed_script: bool
        scripts_present: list of scripts detected
        target_impersonated: str or None
        flags: list of human-readable warnings
        risk_score: risk points contributed (0-50)
    """
    raw = domain_or_url.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
    else:
        host = raw.split("/")[0].split(":")[0]

    host_lower = host.lower()
    is_punycode = "xn--" in host_lower

    # Decode Punycode if present
    unicode_host = host
    if is_punycode:
        try:
            unicode_host = host.encode("ascii").decode("idna")
        except Exception:
            unicode_host = host

    flags = []
    confusables_found = []
    invisibles_found = []
    scripts = set()
    normalized_chars = []
    risk_score = 0

    for idx, ch in enumerate(unicode_host):
        # 1. Check for invisible characters
        if ch in INVISIBLE_CHARS:
            invis = {
                "char": repr(ch),
                "name": INVISIBLE_CHARS[ch],
                "codepoint": f"U+{ord(ch):04X}",
                "index": idx,
            }
            invisibles_found.append(invis)
            continue

        # 2. Check for confusable homoglyphs
        if ch in CONFUSABLES:
            lookalike, script_name = CONFUSABLES[ch]
            confusables_found.append({
                "char": ch,
                "codepoint": f"U+{ord(ch):04X}",
                "name": unicodedata.name(ch, "UNKNOWN"),
                "script": script_name,
                "lookalike": lookalike,
                "index": idx,
            })
            normalized_chars.append(lookalike)
            scripts.add(script_name)
        else:
            normalized_chars.append(ch)
            if ch.isalpha():
                scripts.add(_get_char_script(ch))

    ascii_normalized = "".join(normalized_chars).lower()

    # Mixed script detection (e.g. Latin mixed with Cyrillic or Greek)
    alpha_scripts = {s for s in scripts if s in ("Latin", "Cyrillic", "Greek", "Cherokee")}
    is_mixed_script = len(alpha_scripts) > 1

    # Check if normalized domain targets a known brand
    target_impersonated = None
    # Strip TLD and dots for brand check
    parts = ascii_normalized.split(".")
    for part in parts:
        if part in HIGH_PROFILE_TARGETS:
            target_impersonated = part
            break

    # Build flags and risk score
    has_homoglyphs = len(confusables_found) > 0 or is_punycode

    if is_punycode:
        flags.append(f"Internationalized Domain Name (Punycode): displays as '{unicode_host}'")
        risk_score += 15

    if invisibles_found:
        names = [i["name"] for i in invisibles_found]
        flags.append(f"Contains {len(invisibles_found)} invisible/zero-width character(s): {', '.join(names[:2])}")
        risk_score += 35

    if is_mixed_script:
        flags.append(f"Mixed-script domain detected ({' + '.join(sorted(alpha_scripts))}) — classic IDN homograph attack")
        risk_score += 30

    if confusables_found:
        details = [f"'{c['char']}' ({c['codepoint']} {c['script']}) -> '{c['lookalike']}'" for c in confusables_found[:3]]
        flags.append(f"Contains {len(confusables_found)} confusable Unicode character(s): {', '.join(details)}")
        risk_score += 25

    if target_impersonated and (has_homoglyphs or is_mixed_script):
        flags.append(
            f"Homograph spoofing of high-value brand '{target_impersonated}': visual lookalike resolves to a different character set"
        )
        risk_score += 35

    return {
        "has_homoglyphs": has_homoglyphs or bool(invisibles_found),
        "is_punycode": is_punycode,
        "unicode_domain": unicode_host,
        "ascii_normalized": ascii_normalized,
        "confusable_chars": confusables_found,
        "invisible_chars": invisibles_found,
        "is_mixed_script": is_mixed_script,
        "scripts_present": sorted(list(scripts)),
        "target_impersonated": target_impersonated,
        "flags": flags,
        "risk_score": min(risk_score, 60),
    }


if __name__ == "__main__":
    import json
    import sys

    # Test cases: Cyrillic spoof of google, or punycode xn--pple-43d.com (apple)
    test_input = sys.argv[1] if len(sys.argv) > 1 else "xn--80ak6aa92e.com"  # apple in Cyrillic
    print(json.dumps(detect_homoglyphs(test_input), indent=2))

