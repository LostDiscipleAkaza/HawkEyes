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


_tld_extractor = tldextract.TLDExtract(suffix_list_urls=None)


def _domain(url_str: str) -> str:
    if not url_str:
        return ""
    ext = _tld_extractor(url_str)
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


def _status_name(code: int) -> str:
    names = {
        301: "HTTP 301 (Moved Permanently)",
        302: "HTTP 302 (Found / Temporary)",
        303: "HTTP 303 (See Other)",
        307: "HTTP 307 (Temporary Redirect)",
        308: "HTTP 308 (Permanent Redirect)",
        200: "HTTP 200 (OK)",
    }
    return names.get(code, f"HTTP {code}")


def analyze_redirect_hops(hop_records: list, original_url: str, final_url: str, error: str = None) -> dict:
    """
    Performs deep security analysis on the observed redirect chain:
      - Open redirect parameter exploitation
      - Protocol downgrade (HTTPS -> HTTP)
      - Intermediate domain hopping & cloaking
      - Nested shorteners
      - Client-side (meta / JS) redirection
      - Redirect loops / excessive hops
    """
    flags = []
    risk_score = 0
    domains = []
    seen_domains = set()

    for hop in hop_records:
        dom = hop.get("domain")
        if dom and dom not in seen_domains:
            domains.append(dom)
            seen_domains.add(dom)

    # 1. Check for protocol downgrade (HTTPS -> HTTP)
    downgrade = False
    saw_https = False
    for hop in hop_records:
        sch = hop.get("scheme", "").lower()
        if sch == "https":
            saw_https = True
        elif sch == "http" and saw_https:
            downgrade = True
            break
    if downgrade:
        flags.append("Protocol downgrade detected: redirected from HTTPS to insecure plaintext HTTP")
        risk_score += 25

    # 2. Open redirect detection (query parameter forwarding across domain boundaries)
    open_redirect_param = None
    open_redirect_suspect = False
    for i in range(len(hop_records) - 1):
        cur_hop = hop_records[i]
        next_hop = hop_records[i + 1]
        cur_url = cur_hop.get("url", "")
        next_url = next_hop.get("url", "")
        cur_domain = cur_hop.get("domain", "")
        next_domain = next_hop.get("domain", "")

        if cur_domain and next_domain and cur_domain != next_domain:
            parsed_q = urlparse(cur_url)
            if parsed_q.query:
                qs = parse_qs(parsed_q.query)
                for param, values in qs.items():
                    for v in values:
                        v_unquoted = unquote(v).lower()
                        if next_domain in v_unquoted or (next_url and next_url.lower() in v_unquoted):
                            open_redirect_suspect = True
                            open_redirect_param = param
                            flags.append(
                                f"Suspected open redirect: '{cur_domain}' forwarded to '{next_domain}' "
                                f"via query parameter '{param}'"
                            )
                            risk_score += 30
                            break
                    if open_redirect_suspect:
                        break

    # 3. Intermediate domain hopping & daisy-chaining
    distinct_domains = len(seen_domains)
    if distinct_domains >= 3:
        flags.append(f"Multi-domain hop chain across {distinct_domains} distinct domains ({', '.join(domains[:4])})")
        risk_score += 15

    # 4. Hop count analysis
    hop_count = max(0, len(hop_records) - 1)
    if hop_count >= 5:
        flags.append(f"Excessive redirect chain length ({hop_count} hops) — strong indicator of evasion/cloaking")
        risk_score += 20
    elif hop_count >= 3:
        flags.append(f"Daisy-chained redirects ({hop_count} hops)")
        risk_score += 10

    # 5. Nested shorteners
    shorteners_in_chain = [d for d in domains if d in KNOWN_SHORTENERS]
    if len(shorteners_in_chain) > 1:
        flags.append(f"Nested URL shorteners detected ({' -> '.join(shorteners_in_chain)}) — layered obfuscation")
        risk_score += 20

    # 6. Client-side redirects (meta refresh / JS location)
    client_redirects = [h for h in hop_records if "meta" in str(h.get("type", "")).lower() or "js" in str(h.get("type", "")).lower()]
    has_client_redirect = len(client_redirects) > 0
    if has_client_redirect:
        flags.append("Employs client-side (meta-refresh / JavaScript) redirection to bypass static HTTP crawlers")
        risk_score += 10

    # 7. Loop / error
    if error and "loop" in error.lower():
        flags.append("Circular redirect loop detected")
        risk_score += 20

    return {
        "hops": hop_records,
        "hop_count": hop_count,
        "distinct_domains": domains,
        "distinct_domain_count": distinct_domains,
        "protocol_downgrade": downgrade,
        "open_redirect_suspect": open_redirect_suspect,
        "open_redirect_param": open_redirect_param,
        "has_client_redirect": has_client_redirect,
        "shorteners_used": shorteners_in_chain,
        "flags": flags,
        "risk_score": min(risk_score, 60),
    }


def resolve_redirects(
    url: str, max_redirects: int = 15, timeout: float = 10.0, max_client_hops: int = 5
) -> dict:
    """
    Follows both real HTTP redirects AND client-side (meta-refresh / simple
    JS `location=`) redirects, logging hop status codes and performing
    deep redirect security analysis.
    """
    session = _build_session(max_redirects)
    chain = [url]
    current = url
    last_url = url
    seen = {url}

    # Track structured hop records
    u_init = urlparse(url)
    hop_records = [{
        "hop": 0,
        "url": url,
        "status_code": None,
        "type": "Initial URL",
        "domain": _domain(url),
        "scheme": u_init.scheme,
    }]

    error = None

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
                    verify=False,
                )

            # Record intermediate HTTP 3xx responses
            if resp.history:
                for r in resp.history:
                    if r.url not in chain:
                        chain.append(r.url)
                    # Add hop record if not already logged
                    if not any(h["url"] == r.url for h in hop_records):
                        r_u = urlparse(r.url)
                        hop_records.append({
                            "hop": len(hop_records),
                            "url": r.url,
                            "status_code": r.status_code,
                            "type": _status_name(r.status_code),
                            "domain": _domain(r.url),
                            "scheme": r_u.scheme,
                        })
                if resp.url not in chain:
                    chain.append(resp.url)
                if not any(h["url"] == resp.url for h in hop_records):
                    r_u = urlparse(resp.url)
                    hop_records.append({
                        "hop": len(hop_records),
                        "url": resp.url,
                        "status_code": resp.status_code,
                        "type": _status_name(resp.status_code),
                        "domain": _domain(resp.url),
                        "scheme": r_u.scheme,
                    })
            else:
                # Update initial hop status code if single request
                if hop_records and hop_records[0]["url"] == current:
                    hop_records[0]["status_code"] = resp.status_code

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
            client_type = None
            if is_html_content and client_hops_so_far < max_client_hops:
                body = ""
                try:
                    for chunk in resp.iter_content(chunk_size=8192):
                        body += chunk.decode("utf-8", "ignore")
                        if len(body) >= 65536:
                            break
                except Exception:
                    body = ""
                next_url = _extract_client_redirect(body, resp.url)
                if next_url:
                    if _META_REFRESH_RE.search(body):
                        client_type = "Meta Refresh"
                    elif _JS_REDIRECT_RE.search(body):
                        client_type = "JavaScript Redirect"
                    else:
                        client_type = "Client Interstitial"

            resp.close()

            if not next_url or next_url in seen or len(chain) >= max_redirects:
                break
            seen.add(next_url)
            chain.append(next_url)
            n_u = urlparse(next_url)
            hop_records.append({
                "hop": len(hop_records),
                "url": next_url,
                "status_code": 200,
                "type": client_type or "Client-side Redirect",
                "domain": _domain(next_url),
                "scheme": n_u.scheme,
            })
            last_url = next_url
            current = next_url

        final_url = last_url
        hop_count = len(chain) - 1
        original_host = urlparse(url).hostname or ""
        final_host = urlparse(final_url).hostname or ""

        analysis = analyze_redirect_hops(hop_records, url, final_url)

        return {
            "original_url": url,
            "final_url": final_url,
            "redirect_chain": chain,
            "redirect_count": hop_count,
            "was_redirected": hop_count > 0,
            "cross_domain": original_host != final_host and bool(final_host),
            "analysis": analysis,
        }
    except requests.TooManyRedirects:
        error = f"Exceeded {max_redirects} redirects (possible redirect loop)"
        final_url = last_url
        hop_count = len(chain) - 1
        original_host = urlparse(url).hostname or ""
        final_host = urlparse(final_url).hostname or ""
        analysis = analyze_redirect_hops(hop_records, url, final_url, error=error)
        return {
            "original_url": url,
            "final_url": final_url,
            "redirect_chain": chain,
            "redirect_count": max(hop_count, max_redirects),
            "was_redirected": True,
            "cross_domain": original_host != final_host and bool(final_host),
            "error": error,
            "analysis": analysis,
        }
    except requests.RequestException as e:
        error = _clean_error(e)
        final_url = last_url
        hop_count = len(chain) - 1
        original_host = urlparse(url).hostname or ""
        final_host = urlparse(final_url).hostname or ""
        analysis = analyze_redirect_hops(hop_records, url, final_url, error=error)
        return {
            "original_url": url,
            "final_url": final_url,
            "redirect_chain": chain,
            "redirect_count": hop_count,
            "was_redirected": hop_count > 0,
            "cross_domain": original_host != final_host and bool(final_host),
            "error": error,
            "analysis": analysis,
        }


if __name__ == "__main__":
    import json
    import sys

    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://bit.ly/some-shortlink"
    print(json.dumps(resolve_redirects(test_url), indent=2))
