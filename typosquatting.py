"""
Stage 1.6: Typosquatting Detection
Detects deceptive domain registrations imitating popular brands and high-value
targets using algorithmic typosquatting techniques:
  - Levenshtein / Damerau distance
  - Character omission (gogle.com)
  - Character transposition (googel.com)
  - QWERTY keyboard substitution (payoal.com)
  - Character insertion / duplication (gooogle.com)
  - Combosquatting / hyphenation (paypal-verify.com)
  - Bitsquatting (single bit-flip)
"""
from difflib import SequenceMatcher

# Target brand catalog: brand name -> (primary registered domain, set of official domains)
BRAND_TARGETS = {
    "google": ("google.com", {"google.com", "google.co.uk", "google.ca", "google.de", "google.fr", "google.co.in", "gstatic.com", "googleapis.com", "gmail.com", "youtube.com"}),
    "paypal": ("paypal.com", {"paypal.com", "paypal.me", "paypalobjects.com"}),
    "microsoft": ("microsoft.com", {"microsoft.com", "live.com", "office.com", "msn.com", "outlook.com", "azure.com", "bing.com", "office365.com", "windows.com"}),
    "apple": ("apple.com", {"apple.com", "icloud.com", "apple-dns.net", "mzstatic.com"}),
    "amazon": ("amazon.com", {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazonaws.com", "primevideo.com", "amazonpay.com"}),
    "netflix": ("netflix.com", {"netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net"}),
    "facebook": ("facebook.com", {"facebook.com", "fb.com", "messenger.com", "meta.com", "fbcdn.net"}),
    "instagram": ("instagram.com", {"instagram.com", "cdninstagram.com"}),
    "whatsapp": ("whatsapp.com", {"whatsapp.com", "whatsapp.net"}),
    "twitter": ("twitter.com", {"twitter.com", "x.com", "twimg.com", "t.co"}),
    "linkedin": ("linkedin.com", {"linkedin.com", "licdn.com"}),
    "dropbox": ("dropbox.com", {"dropbox.com", "dropboxapi.com", "dropboxstatic.com"}),
    "github": ("github.com", {"github.com", "githubassets.com", "githubusercontent.com"}),
    "gitlab": ("gitlab.com", {"gitlab.com"}),
    "yahoo": ("yahoo.com", {"yahoo.com", "yimg.com"}),
    "binance": ("binance.com", {"binance.com", "binance.org", "binance.vision"}),
    "coinbase": ("coinbase.com", {"coinbase.com", "coinbase.pro"}),
    "metamask": ("metamask.io", {"metamask.io"}),
    "kraken": ("kraken.com", {"kraken.com"}),
    "spotify": ("spotify.com", {"spotify.com", "scdn.co"}),
    "discord": ("discord.com", {"discord.com", "discordapp.com", "discord.gg"}),
    "telegram": ("telegram.org", {"telegram.org", "t.me"}),
    "ebay": ("ebay.com", {"ebay.com", "ebayimg.com"}),
    "walmart": ("walmart.com", {"walmart.com", "walmartimages.com"}),
    "chase": ("chase.com", {"chase.com", "jpmorganchase.com"}),
    "wellsfargo": ("wellsfargo.com", {"wellsfargo.com"}),
    "bankofamerica": ("bankofamerica.com", {"bankofamerica.com", "bofa.com"}),
    "citibank": ("citibank.com", {"citibank.com", "citi.com"}),
    "hdfcbank": ("hdfcbank.com", {"hdfcbank.com"}),
    "icicibank": ("icicibank.com", {"icicibank.com"}),
    "paytm": ("paytm.com", {"paytm.com"}),
    "phonepe": ("phonepe.com", {"phonepe.com"}),
    "steam": ("steampowered.com", {"steampowered.com", "steamcommunity.com"}),
    "zoom": ("zoom.us", {"zoom.us", "zoom.com"}),
    "slack": ("slack.com", {"slack.com"}),
    "adobe": ("adobe.com", {"adobe.com"}),
}

# QWERTY adjacent keyboard map for typo modeling
QWERTY_NEIGHBORS = {
    "q": ["w", "a", "s"],
    "w": ["q", "e", "a", "s", "d"],
    "e": ["w", "r", "s", "d"],
    "r": ["e", "t", "d", "f"],
    "t": ["r", "y", "f", "g"],
    "y": ["t", "u", "g", "h"],
    "u": ["y", "i", "h", "j"],
    "i": ["u", "o", "j", "k"],
    "o": ["i", "p", "k", "l"],
    "p": ["o", "l"],
    "a": ["q", "w", "s", "z"],
    "s": ["a", "d", "w", "e", "z", "x"],
    "d": ["s", "f", "e", "r", "x", "c"],
    "f": ["d", "g", "r", "t", "c", "v"],
    "g": ["f", "h", "t", "y", "v", "b"],
    "h": ["g", "j", "y", "u", "b", "n"],
    "j": ["h", "k", "u", "i", "n", "m"],
    "k": ["j", "l", "i", "o", "m"],
    "l": ["k", "o", "p"],
    "z": ["a", "s", "x"],
    "x": ["z", "s", "d", "c"],
    "c": ["x", "d", "f", "v"],
    "v": ["c", "f", "g", "b"],
    "b": ["v", "g", "h", "n"],
    "n": ["b", "h", "j", "m"],
    "m": ["n", "j", "k"],
}

SENSITIVE_MODIFIERS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "support", "help", "auth", "portal", "service",
    "wallet", "billing", "recover", "unlock", "alert", "official",
}


def _levenshtein(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _check_bitsquatting(s1: str, s2: str) -> bool:
    """Checks if two strings of identical length differ by exactly 1 flipped bit."""
    if len(s1) != len(s2):
        return False
    diff_count = 0
    for c1, c2 in zip(s1, s2):
        diff = ord(c1) ^ ord(c2)
        if diff != 0:
            # Check if diff is power of two (single bit)
            if diff & (diff - 1) == 0:
                diff_count += 1
            else:
                return False
    return diff_count == 1


def detect_typosquatting(domain: str, registered_domain: str = None) -> dict:
    """
    Checks if a domain is an intentional typosquat or combosquat targeting a
    known brand or service.

    Returns:
        is_typosquat: bool
        matched_brand: str or None
        official_domain: str or None
        technique: str or None
        similarity_score: float (0.0 to 1.0)
        distance: int
        description: str or None
        flags: list[str]
        risk_score: int (0-40)
    """
    target_label = (domain or "").lower().strip()
    reg_dom = (registered_domain or domain or "").lower().strip()

    if not target_label:
        return {
            "is_typosquat": False,
            "matched_brand": None,
            "official_domain": None,
            "technique": None,
            "similarity_score": 0.0,
            "distance": 0,
            "description": None,
            "flags": [],
            "risk_score": 0,
        }

    # Extract primary label (without TLD)
    main_label = target_label.split(".")[0]

    flags = []
    risk_score = 0
    best_match = None

    for brand, (primary_dom, official_set) in BRAND_TARGETS.items():
        # If the domain is legitimately an official domain of this brand, skip
        if reg_dom in official_set or any(reg_dom.endswith("." + off) for off in official_set):
            continue

        brand_len = len(brand)
        label_len = len(main_label)

        # 1. Combosquatting: brand combined with sensitive modifier (e.g. paypal-login, google-verify)
        if brand in main_label and main_label != brand:
            # Check for hyphens or keyword combinations
            sub_parts = main_label.replace("-", ".").replace("_", ".").split(".")
            for part in sub_parts:
                if part in SENSITIVE_MODIFIERS:
                    match_info = {
                        "brand": brand,
                        "official": primary_dom,
                        "technique": "combosquatting",
                        "similarity": 0.95,
                        "distance": abs(label_len - brand_len),
                        "desc": f"Combines target brand '{brand}' with security keyword '{part}'",
                        "risk": 35,
                    }
                    if not best_match or match_info["risk"] > best_match["risk"]:
                        best_match = match_info
                    break

        # 2. Bitsquatting (single bit-flip)
        if label_len == brand_len and _check_bitsquatting(main_label, brand):
            match_info = {
                "brand": brand,
                "official": primary_dom,
                "technique": "bitsquatting",
                "similarity": 0.90,
                "distance": 1,
                "desc": f"Single bit-flip mutation of '{brand}' (bitsquatting)",
                "risk": 30,
            }
            if not best_match or match_info["risk"] > best_match["risk"]:
                best_match = match_info

        # 3. Exact character omission (1 missing letter, e.g. gogle -> google)
        if label_len == brand_len - 1 and brand_len >= 5:
            for i in range(brand_len):
                omitted = brand[:i] + brand[i + 1:]
                if main_label == omitted:
                    match_info = {
                        "brand": brand,
                        "official": primary_dom,
                        "technique": "omission",
                        "similarity": 0.92,
                        "distance": 1,
                        "desc": f"Character omission typo of '{brand}' (missing '{brand[i]}')",
                        "risk": 30,
                    }
                    if not best_match or match_info["risk"] > best_match["risk"]:
                        best_match = match_info
                    break

        # 4. Adjacent character transposition (swapped letters, e.g. googel -> google)
        if label_len == brand_len and brand_len >= 4:
            for i in range(brand_len - 1):
                transposed = list(brand)
                transposed[i], transposed[i + 1] = transposed[i + 1], transposed[i]
                if main_label == "".join(transposed):
                    match_info = {
                        "brand": brand,
                        "official": primary_dom,
                        "technique": "transposition",
                        "similarity": 0.92,
                        "distance": 1,
                        "desc": f"Transposition typo of '{brand}' (swapped '{brand[i]}' and '{brand[i+1]}')",
                        "risk": 30,
                    }
                    if not best_match or match_info["risk"] > best_match["risk"]:
                        best_match = match_info
                    break

        # 5. QWERTY keyboard substitution
        if label_len == brand_len and brand_len >= 4:
            diff_indices = [i for i in range(brand_len) if main_label[i] != brand[i]]
            if len(diff_indices) == 1:
                idx = diff_indices[0]
                expected_char = brand[idx]
                actual_char = main_label[idx]
                if actual_char in QWERTY_NEIGHBORS.get(expected_char, []):
                    match_info = {
                        "brand": brand,
                        "official": primary_dom,
                        "technique": "qwerty_substitution",
                        "similarity": 0.90,
                        "distance": 1,
                        "desc": f"Adjacent keyboard typo of '{brand}' ('{actual_char}' instead of '{expected_char}')",
                        "risk": 30,
                    }
                    if not best_match or match_info["risk"] > best_match["risk"]:
                        best_match = match_info

        # 6. Character insertion / duplication (e.g. gooogle, paypaal)
        if label_len == brand_len + 1 and brand_len >= 4:
            for i in range(label_len):
                sub = main_label[:i] + main_label[i + 1:]
                if sub == brand:
                    match_info = {
                        "brand": brand,
                        "official": primary_dom,
                        "technique": "insertion",
                        "similarity": 0.88,
                        "distance": 1,
                        "desc": f"Character insertion / repetition typo of '{brand}' (added '{main_label[i]}')",
                        "risk": 25,
                    }
                    if not best_match or match_info["risk"] > best_match["risk"]:
                        best_match = match_info
                    break

        # 7. General Levenshtein distance 1 or 2 for long brands
        if not best_match and brand_len >= 5 and abs(label_len - brand_len) <= 2:
            dist = _levenshtein(main_label, brand)
            ratio = SequenceMatcher(None, main_label, brand).ratio()
            if dist == 1 and ratio >= 0.80:
                match_info = {
                    "brand": brand,
                    "official": primary_dom,
                    "technique": "levenshtein_edit_1",
                    "similarity": round(ratio, 2),
                    "distance": 1,
                    "desc": f"High similarity edit distance 1 lookalike of '{brand}'",
                    "risk": 25,
                }
                best_match = match_info
            elif dist == 2 and brand_len >= 7 and ratio >= 0.82:
                match_info = {
                    "brand": brand,
                    "official": primary_dom,
                    "technique": "levenshtein_edit_2",
                    "similarity": round(ratio, 2),
                    "distance": 2,
                    "desc": f"Similar edit distance 2 lookalike of '{brand}'",
                    "risk": 15,
                }
                best_match = match_info

    if best_match:
        flags.append(
            f"Typosquatting detected: domain mimics '{best_match['brand']}' "
            f"({best_match['desc']}) — official domain is {best_match['official']}"
        )
        return {
            "is_typosquat": True,
            "matched_brand": best_match["brand"],
            "official_domain": best_match["official"],
            "technique": best_match["technique"],
            "similarity_score": best_match["similarity"],
            "distance": best_match["distance"],
            "description": best_match["desc"],
            "flags": flags,
            "risk_score": best_match["risk"],
        }

    return {
        "is_typosquat": False,
        "matched_brand": None,
        "official_domain": None,
        "technique": None,
        "similarity_score": 0.0,
        "distance": 0,
        "description": None,
        "flags": [],
        "risk_score": 0,
    }


if __name__ == "__main__":
    import json
    import sys

    test_domain = sys.argv[1] if len(sys.argv) > 1 else "paypaal.com"
    print(json.dumps(detect_typosquatting(test_domain), indent=2))

