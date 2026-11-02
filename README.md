# URL Scanner — v1 (CLI)

A modular URL risk-scoring pipeline. Runs entirely in the terminal — no server, no browser.

## Pipeline

```
URL parser → Redirect resolution (unmask shorteners) → DNS → TLS → WHOIS/RDAP → URL heuristics → VirusTotal → urlscan.io → Risk score → Terminal report
```

Shortened or cloaked links (bit.ly, tinyurl, t.co, redirect chains) are followed
all the way to their real destination first — everything downstream scans the
**actual landing page**, not the wrapper link. The report shows the full
redirect chain so you can see exactly where a link really goes.

Each stage lives in its own file and can be run standalone (`python <file>.py <url>`)
or through the full pipeline (`pipeline.py` / `scan.py`).

## Files

| File | Stage |
|---|---|
| `url_parser.py` | Normalizes and splits the URL into components |
| `redirect_resolver.py` | Follows redirects to unmask shorteners/cloaked links (bit.ly, tinyurl, etc.) |
| `dns_lookup.py` | Resolves A/AAAA/MX/NS/TXT records |
| `tls_check.py` | TLS handshake + certificate inspection |
| `whois_lookup.py` | Domain registration age/registrar/name servers |
| `heuristics.py` | Offline rules engine (IP hosts, `@`, hyphens, suspicious TLDs, keywords...) |
| `virustotal.py` | VirusTotal v3 API client |
| `urlscan.py` | urlscan.io API client (live sandboxed scan) |
| `risk_score.py` | Aggregates every stage into a 0–100 score + verdict |
| `pipeline.py` | Orchestrates all of the above |
| `report.py` | Formats results into a colorized terminal report |
| `scan.py` | **CLI entry point — run this** |

## Setup

```bash
pip install -r requirements.txt
```

Set API keys as environment variables (both are free tier):

```bash
export VT_API_KEY="your_virustotal_api_key"        # https://www.virustotal.com/gui/join-us
export URLSCAN_API_KEY="your_urlscan_api_key"      # https://urlscan.io/user/signup
```

The scanner still works without these — VT/urlscan sections will just report
"not configured" and the risk score falls back on DNS/TLS/WHOIS/heuristics.

## Run

```bash
python scan.py http://example.com
```

Options:

```bash
python scan.py <url> --full-scan     # extended analysis: polls VT (up to 60s) & urlscan.io (up to 45s)
python scan.py <url> --scan          # also run a live urlscan.io scan (~15-30s)
python scan.py <url> --vt-wait 60    # custom timeout (seconds) for VirusTotal completion
python scan.py <url> --urlscan-wait 45 # custom timeout (seconds) for urlscan.io polling
python scan.py <url> --json          # raw JSON output instead of the formatted report
python scan.py <url> --no-color      # plain text, no ANSI colors (good for logging to a file)
python scan.py <url> --no-redirect   # scan the given URL as-is, skip unmasking
python scan.py <url> --no-vt-wait    # don't wait for VirusTotal analysis (instant return)
```

Exit code is `0` for score < 40, `1` for score >= 40 — handy for scripting or CI gating.

## Run a single stage from the CLI

```bash
python pipeline.py http://example.com          # full pipeline, no urlscan, raw JSON
python heuristics.py                            # test the heuristics engine alone
```

## Notes

- `urlscan.io` scanning is opt-in (`--scan` flag) since it takes ~15 seconds
  per scan (it waits for the sandboxed page load to finish).
- VirusTotal auto-submits URLs it hasn't seen before, so the first check on
  a brand-new URL will say "submitted" — re-scan a minute later for a verdict.
- All API keys are read from environment variables, never hardcoded.

## Roadmap (v2)

URLhaus feed matching, Google Safe Browsing, redirect-chain following,
typosquatting/homoglyph detection, certificate transparency log search,
persistent scan history, and a threat graph view — all as additional
stages feeding into `risk_score.py`.
