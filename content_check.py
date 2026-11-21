"""
Stage 5.5: Page content analysis
Everything else in the pipeline judges the URL and the infrastructure
around it. This stage looks at the PAGE ITSELF, because that is where
phishing kits actually give themselves away: a credential form on a
throwaway host, a form posting to somewhere else, a page titled
"Instagram" that is not on instagram.com, or scripts asking for
camera / microphone / location access.

It fetches the final (already unmasked) URL once, reads at most ~256 KB,
and also reads up to a few same-origin <script src> files, since kits
often keep their JavaScript in a separate file.
"""
import html
import re
import warnings
from urllib.parse import urljoin, urlparse

import requests
import tldextract

from heuristics import find_brand_in_text
from redirect_resolver import DEFAULT_HEADERS, _clean_error

MAX_PAGE_BYTES = 262144
MAX_SCRIPT_BYTES = 131072
MAX_SCRIPTS = 4

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_PASSWORD_RE = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?password", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_ACTION_RE = re.compile(r"\baction\s*=\s*[\"']?([^\"'\s>]*)", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_MEDIA_RE = re.compile(
    r"getUserMedia|mediaDevices|navigator\.geolocation|getCurrentPosition", re.IGNORECASE
)


_tld_extractor = tldextract.TLDExtract(suffix_list_urls=None)


def _reg(url: str) -> str:
    return _tld_extractor(url).registered_domain.lower()


def _label(url: str) -> str:
    return _tld_extractor(url).domain.lower()


def _read_limited(resp, limit: int) -> str:
    body = ""
    try:
        for chunk in resp.iter_content(chunk_size=8192):
            body += chunk.decode("utf-8", "ignore")
            if len(body) >= limit:
                break
    except Exception:
        pass
    return body


def analyze_html(body: str, page_url: str, extra_js: str = "") -> dict:
    """Pure analysis (no network) so it can be unit-tested on its own."""
    flags = []
    score = 0

    m = _TITLE_RE.search(body)
    title = html.unescape(m.group(1)).strip()[:120] if m else ""

    has_password = bool(_PASSWORD_RE.search(body))
    if has_password:
        flags.append("Page contains a password input field (credential form)")
        score += 30

    actions = []
    for fm in _FORM_RE.finditer(body):
        am = _ACTION_RE.search(fm.group(0))
        if am and am.group(1) and not am.group(1).startswith(("#", "javascript:")):
            actions.append(urljoin(page_url, html.unescape(am.group(1))))
    page_reg = _reg(page_url)
    foreign = [a for a in actions if a.startswith("http") and _reg(a) and _reg(a) != page_reg]
    if foreign:
        flags.append(f"Form submits data to a different domain ({_reg(foreign[0])})")
        score += 25

    if _MEDIA_RE.search(body) or _MEDIA_RE.search(extra_js):
        flags.append("Page script requests camera / microphone / location access")
        score += 25

    brand = find_brand_in_text(title, _label(page_url)) if title else None
    if brand:
        flags.append(f"Page title mentions '{brand}' but the domain is not {brand}'s")
        score += 25

    return {
        "title": title,
        "has_password_field": has_password,
        "form_actions": actions[:5],
        "flags": flags,
        "score": min(score, 60),
    }


def check_content(url: str, timeout: float = 10.0) -> dict:
    if not url:
        return {"skipped": True}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            resp = requests.get(
                url, headers=DEFAULT_HEADERS, timeout=timeout,
                stream=True, verify=False, allow_redirects=True,
            )
        ctype = resp.headers.get("Content-Type", "").lower()
        status = resp.status_code
        final_url = resp.url
        if ctype and "html" not in ctype and "text/plain" not in ctype:
            resp.close()
            return {"fetched": True, "status": status, "flags": [], "score": 0,
                    "note": f"Non-HTML content ({ctype.split(';')[0]}), not analyzed"}
        body = _read_limited(resp, MAX_PAGE_BYTES)
        resp.close()
    except requests.RequestException as e:
        return {"error": f"Could not fetch page content: {_clean_error(e)}"}

    # Same-origin scripts only: never chase third-party hosts from here.
    extra_js = ""
    host = urlparse(final_url).hostname
    seen = 0
    for src in _SCRIPT_SRC_RE.findall(body):
        if seen >= MAX_SCRIPTS:
            break
        script_url = urljoin(final_url, html.unescape(src))
        if urlparse(script_url).hostname != host:
            continue
        seen += 1
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                sr = requests.get(script_url, headers=DEFAULT_HEADERS, timeout=timeout,
                                  stream=True, verify=False)
            extra_js += _read_limited(sr, MAX_SCRIPT_BYTES)
            sr.close()
        except requests.RequestException:
            continue

    result = analyze_html(body, final_url, extra_js)
    result.update({"fetched": True, "status": status, "final_url": final_url})
    return result


if __name__ == "__main__":
    import json
    import sys

    print(json.dumps(check_content(sys.argv[1] if len(sys.argv) > 1 else "http://example.com"), indent=2))