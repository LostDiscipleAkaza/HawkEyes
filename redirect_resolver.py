"""
Stage 0.5: Redirect resolution (link unmasking)
Follows the full redirect chain of a URL so that shorteners (bit.ly,
tinyurl, t.co...) and other cloaking redirects don't hide the real
destination from the rest of the pipeline. Everything downstream
(DNS/TLS/WHOIS/heuristics/VT/urlscan) should be run against the
*resolved* final URL, not the wrapper link the user was given.

IMPORTANT: this stage deliberately does NOT verify TLS certificates.
Its only job is to find out where a link actually goes - not to judge
whether that destination is trustworthy. Trust judgment belongs to
tls_check.py, which verifies properly. If this stage verified certs
too, a phishing link that happens to sit behind (or land on) a host
with a broken/self-signed cert would fail to resolve at all, and the
real destination - the whole point of this feature - would never be
discovered. So: resolve first, judge separately.
"""
import html
import re
import warnings
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests
import tldextract
import urllib3
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:  # older urllib3
    from requests.packages.urllib3.util.retry import Retry

# We intentionally disable cert verification for this stage only (see
# module docstring), so silence the resulting urllib3 warning noise.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    # Look like a real browser request. Some shorteners/cloakers and most
    # WAFs (Cloudflare, etc.) will drop or reset connections from requests
    # that don't look like a normal browser - a bare User-Agent alone often
    # isn't enough, so send a fuller, more realistic header set.
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# Matches <meta http-equiv="refresh" content="0; url=https://real-site.com">
# or <meta content="0; url=https://real-site.com" http-equiv="refresh">
_META_REFRESH_RE = re.compile(
    r'<meta\s+[^>]*?(?:http-equiv=["\']?refresh["\']?[^>]*?content=["\']?([^"\'\s>]+.*?)|content=["\']?([^"\'\s>]+.*?)[^>]*?http-equiv=["\']?refresh["\']?)[^>]*?>',
    re.IGNORECASE,
)
# Matches window.location = "..." / location.replace(...) / location.assign(...) / navigate(...)
_JS_REDIRECT_RE = re.compile(
    r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']'
    r'|(?:window\.)?location\.(?:replace|assign)\(\s*["\']([^"\']+)["\']\s*\)'
    r'|(?:window\.)?navigate\(\s*["\']([^"\']+)["\']\s*\)'
    r'|self\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']'
    r'|top\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
# Matches LinkedIn external link buttons and tracking anchors
_LINKEDIN_CLICK_RE = re.compile(
    r'<a\s+[^>]*?data-tracking-control-name=["\']external_url_click["\'][^>]*?href=["\']([^"\']+)["\']'
    r'|<a\s+[^>]*?href=["\']([^"\']+)["\'][^>]*?data-tracking-control-name=["\']external_url_click["\']',
    re.IGNORECASE,
)
# General anchor tag matcher
_A_HREF_RE = re.compile(
    r'<a\s+[^>]*?href=["\']([^"\']+)["\'][^>]*?>',
    re.IGNORECASE,
)

REDIRECT_QUERY_PARAMS = (
    "url", "target", "dest", "destination", "redirect", "redirect_to",
    "r", "u", "q", "link", "next",
)


def _domain(url_str: str) -> str:
    if not url_str:
        return ""
    ext = tldextract.extract(url_str)
    return (getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or "").lower()


def _extract_query_redirect(url: str) -> str:
    """Extract destination URL from common wrapper query parameters
    (e.g. ?url=..., ?q=..., ?u=...)."""
    parsed = urlparse(url)
    if not parsed.query:
        return None
    qs = parse_qs(parsed.query)
    for param in REDIRECT_QUERY_PARAMS:
        if param in qs and qs[param]:
            val = unquote(qs[param][0]).strip()
            if val.startswith(("http://", "https://")):
                return val
    return None


KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "lnkd.in", "linktr.ee", "cutt.ly", "shorturl.at", "t.ly", "rb.gy", "bitly.com",
}

INTERSTITIAL_STRONG_PHRASES = (
    "redirect notice",
    "you are now leaving",
    "is trying to send you to",
    "this link will take you to",
    "you will be redirected to",
    "you are about to be redirected",
    "if you are not redirected",
    "if you're not redirected",
    "click here to be redirected",
    "click here if you are not redirected",
    "external link disclaimer",
    "link warning",
    "outgoing link",
)

EXCLUDED_INTERSTITIAL_DOMAINS = {
    "google.com", "facebook.com", "twitter.com", "x.com", "instagram.com",
    "youtube.com", "wikimedia.org", "wikipedia.org", "w3.org", "creativecommons.org",
}


def _extract_client_redirect(html_body: str, base_url: str):
    """Look for client-side redirects (meta-refresh, JS redirects, LinkedIn
    interstitials, or shortener redirect pages) that an HTTP client wouldn't
    follow via standard 3xx response codes."""
    if not html_body:
        return None

    base_domain = _domain(base_url)
    lower_body = html_body.lower()
    is_short_page = len(html_body) < 15000
    is_shortener_domain = base_domain in KNOWN_SHORTENERS

    # 1. Meta refresh
    m_meta = _META_REFRESH_RE.search(html_body)
    if m_meta:
        raw_content = m_meta.group(1) or m_meta.group(2) or ""
        delay_match = re.search(r"^\s*(\d+)", raw_content)
        delay = int(delay_match.group(1)) if delay_match else 0
        if delay <= 5:
            m_url = re.search(r'url\s*=\s*["\']?([^"\'\s;>]+)', raw_content, re.IGNORECASE)
            if m_url:
                target = html.unescape(m_url.group(1).strip().strip('"\''))
                if not target.startswith(("javascript:", "#", "mailto:")):
                    return urljoin(base_url, target)

    # 2. JavaScript redirect: only run if the page is short (interstitial/wrapper)
    # or the domain is a known shortener. Normal large pages (news, wikis) frequently
    # have inline analytics or script functions referencing window.location.
    if is_short_page or is_shortener_domain:
        m_js = _JS_REDIRECT_RE.search(html_body)
        if m_js:
            target = m_js.group(1) or m_js.group(2) or m_js.group(3) or m_js.group(4) or m_js.group(5)
            if target:
                target = html.unescape(target.strip())
                if not target.startswith(("javascript:", "#", "mailto:")):
                    return urljoin(base_url, target)

    # 3. LinkedIn interstitial / explicit external link button
    m_li = _LINKEDIN_CLICK_RE.search(html_body)
    if m_li:
        target = m_li.group(1) or m_li.group(2)
        if target:
            return html.unescape(target.strip())

    # 4. LinkedIn interstitial page (lnkd.in or linkedin.com wrapper)
    is_linkedin = (
        "lnkd.in" in base_domain
        or "linkedin.com" in base_domain
        or "external_link_redirect_interstitial" in lower_body
        or "not on linkedin" in lower_body
    )
    if is_linkedin:
        for m in _A_HREF_RE.finditer(html_body):
            raw_href = html.unescape(m.group(1).strip())
            if raw_href.startswith(("http://", "https://")):
                dest_domain = _domain(raw_href)
                if dest_domain and dest_domain not in ("linkedin.com", "licdn.com", "lnkd.in"):
                    return raw_href

    # 5. Generic redirect notice / interstitial pages
    # CRITICAL: Only evaluate interstitials on short pages or known wrapper domains,
    # and require strong phrasing (e.g. "redirect notice", not bare "external link").
    if is_short_page or is_shortener_domain:
        is_interstitial = any(phrase in lower_body for phrase in INTERSTITIAL_STRONG_PHRASES)
        if is_interstitial:
            for m in _A_HREF_RE.finditer(html_body):
                raw_href = html.unescape(m.group(1).strip())
                if raw_href.startswith(("http://", "https://")):
                    dest_domain = _domain(raw_href)
                    if dest_domain and dest_domain != base_domain:
                        if dest_domain not in EXCLUDED_INTERSTITIAL_DOMAINS:
                            return raw_href

    # 6. Fallback: inspect base_url query parameters for destination URL
    q_target = _extract_query_redirect(base_url)
    if q_target:
        dest_domain = _domain(q_target)
        if dest_domain and dest_domain != base_domain:
            return q_target

    return None


def _build_session(max_redirects: int) -> requests.Session:
    session = requests.Session()
    session.max_redirects = max_redirects
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "HEAD"]),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _clean_error(e: Exception) -> str:
    """requests wraps low-level exceptions in noisy nested reprs
    (e.g. ("Connection aborted.", RemoteDisconnected(...))) - unwrap the
    common ones to a plain, readable message."""
    msg = str(e)
    if isinstance(e, requests.exceptions.ConnectionError):
        if "RemoteDisconnected" in msg or "Connection aborted" in msg:
            return "Server closed the connection without responding (likely bot/WAF protection)"
        if "NameResolutionError" in msg or "Failed to resolve" in msg:
            return "Could not resolve hostname (DNS lookup failed)"
        if "Connection refused" in msg:
            return "Connection refused by host"
    if isinstance(e, requests.exceptions.Timeout):
        return "Connection timed out"
    return msg


def resolve_redirects(
    url: str, max_redirects: int = 15, timeout: float = 10.0, max_client_hops: int = 5
) -> dict:
    """
    Follows both real HTTP redirects AND client-side (meta-refresh / simple
    JS `location=`) redirects, since many shorteners use an interstitial
    page rather than a true 3xx - a plain HTTP client would otherwise
    report "no redirect" while actually landing on the wrapper page
    instead of the real destination.

    Returns:
        original_url: the URL as given
        final_url: where it actually ends up after all redirects
        redirect_chain: ordered list of every URL hit along the way
        redirect_count: number of hops (HTTP + client-side combined)
        was_redirected: bool
        cross_domain: True if final_url's host differs from the original host
        error: set if the request failed outright (timeout, DNS failure, WAF block, etc.)
    """
    session = _build_session(max_redirects)
    chain = [url]  # only ever grows for GENUINE hops (real redirects), not URL normalization
    current = url
    last_url = url  # tracks where we actually ended up, including harmless normalization
    seen = {url}

    try:
        while True:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                resp = session.get(
                    current,
                    allow_redirects=True,
                    timeout=timeout,
                    headers=DEFAULT_HEADERS,
                    stream=True,
                    verify=False,  # see module docstring - resolving, not judging trust
                )

            # Only count this as a hop if a real HTTP redirect actually occurred.
            # Without that, resp.url can still differ from the request URL due
            # to harmless normalization (e.g. "example.com" -> "example.com/"),
            # which is NOT a redirect and shouldn't be reported as one.
            if resp.history:
                for r in resp.history:
                    if r.url not in chain:
                        chain.append(r.url)
                if resp.url not in chain:
                    chain.append(resp.url)
            last_url = resp.url

            next_url = None
            content_type = resp.headers.get("Content-Type", "").lower()
            client_hops_so_far = len(chain) - 1
            is_html_content = (
                not content_type
                or "text/html" in content_type
                or "text/plain" in content_type
                or "xml" in content_type
            )
            if is_html_content and client_hops_so_far < max_client_hops:
                body = ""
                try:
                    for chunk in resp.iter_content(chunk_size=8192):
                        body += chunk.decode("utf-8", "ignore")
                        if len(body) >= 65536:  # plenty for headers and interstitial body
                            break
                except Exception:
                    body = ""
                next_url = _extract_client_redirect(body, resp.url)

            resp.close()

            if not next_url or next_url in seen or len(chain) >= max_redirects:
                break
            seen.add(next_url)
            chain.append(next_url)
            last_url = next_url
            current = next_url

        final_url = last_url
        hop_count = len(chain) - 1
        original_host = urlparse(url).hostname or ""
        final_host = urlparse(final_url).hostname or ""

        return {
            "original_url": url,
            "final_url": final_url,
            "redirect_chain": chain,
            "redirect_count": hop_count,
            "was_redirected": hop_count > 0,
            "cross_domain": original_host != final_host and bool(final_host),
        }
    except requests.TooManyRedirects:
        final_url = last_url
        hop_count = len(chain) - 1
        original_host = urlparse(url).hostname or ""
        final_host = urlparse(final_url).hostname or ""
        return {
            "original_url": url,
            "final_url": final_url,
            "redirect_chain": chain,
            "redirect_count": max(hop_count, max_redirects),
            "was_redirected": True,
            "cross_domain": original_host != final_host and bool(final_host),
            "error": f"Exceeded {max_redirects} redirects (possible redirect loop)",
        }
    except requests.RequestException as e:
        final_url = last_url
        hop_count = len(chain) - 1
        original_host = urlparse(url).hostname or ""
        final_host = urlparse(final_url).hostname or ""
        return {
            "original_url": url,
            "final_url": final_url,
            "redirect_chain": chain,
            "redirect_count": hop_count,
            "was_redirected": hop_count > 0,
            "cross_domain": original_host != final_host and bool(final_host),
            "error": _clean_error(e),
        }


if __name__ == "__main__":
    import json
    import sys

    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://bit.ly/some-shortlink"
    print(json.dumps(resolve_redirects(test_url), indent=2))
