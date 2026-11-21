"""
Stage 1: URL Parser
Normalizes a raw input string into a URL and breaks it into components
(scheme, host, path, query, subdomain/domain/suffix) that every later
stage depends on.
"""
from urllib.parse import urlparse
import tldextract

_extractor = tldextract.TLDExtract(suffix_list_urls=None)


def parse_url(raw_url: str) -> dict:
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    ext = _extractor(url)

    return {
        "original_url": url,
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "hostname": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "subdomain": ext.subdomain,
        "domain": ext.domain,
        "suffix": ext.suffix,
        "registered_domain": getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain,
    }


if __name__ == "__main__":
    import json
    import sys

    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://login-secure.paypal.verify-account.xyz/reset"
    print(json.dumps(parse_url(test_url), indent=2))
