# URL Scanner — v2 (CLI)

A modular, enterprise-grade URL security analysis and risk-scoring pipeline. Runs entirely in the terminal — no mandatory server or browser required.

## Pipeline Architecture

```
URL parser
  │
  ├──> Redirect Analysis (unmask shorteners, hop tracking, open redirects, protocol downgrades)
  │      │
  │      └──> Real Destination URL
  │             ├──> Homoglyph & IDN Detection (confusables, Punycode, mixed scripts)
  │             ├──> Typosquatting Detection (Levenshtein, omission, combosquatting, bitsquatting)
  │             ├──> DNS Lookup (A, AAAA, MX, NS, TXT)
  │             ├──> TLS Handshake & Cert Inspection (validity, self-signed, expiration)
  │             ├──> Certificate Transparency (crt.sh logs, issuance churn, subdomains)
  │             ├──> WHOIS / RDAP (registration age, registrar)
  │             ├──> URL Heuristics (offline rules engine)
  │             ├──> Page Content Analysis (forms, camera/location, credentials)
  │             ├──> Phishing Detection (brand targeting, webhook exfiltration drops, kit signatures)
  │             ├──> VirusTotal v3 (multi-engine verdicts)
  │             ├──> URLhaus (abuse.ch malware intelligence)
  │             ├──> Google Safe Browsing v4 (threat blacklist)
  │             └──> urlscan.io (live sandboxed DOM scan)
  │
  └──> Composite Risk Score (0-100 score, verdict, categorized reasons)
  │
  ├──> Threat Relationship Graph (ASCII tree, interactive HTML, DOT, JSON)
  └──> Persistent Scan History (SQLite storage, search, export)
```

## Features & Modules

| Module | Feature / Description |
|---|---|
| `redirect_resolver.py` | **Redirect Analysis**: Unmasks shorteners (bit.ly, t.co), follows client-side meta-refresh & JS redirects, logs per-hop HTTP status codes, flags open redirects and HTTPS-to-HTTP downgrades |
| `homoglyph.py` | **Homoglyph & IDN Detection**: Detects Punycode (`xn--`), confusable Unicode characters (Cyrillic, Greek, fullwidth), zero-width invisible characters, and mixed-script brand spoofing |
| `typosquatting.py` | **Typosquatting Detection**: Catches domain impersonation via omission, transposition, QWERTY substitution, repetition, combosquatting (`paypal-verify`), bitsquatting, and Levenshtein edit distance |
| `phishing_detector.py` | **Phishing Detection Engine**: Flags credential harvesting forms, known exfiltration endpoints (Discord webhooks, Telegram bots, Formspree), packed/obfuscated JS (`eval/unescape`), and urgency lures |
| `urlhaus.py` | **URLhaus Integration**: Queries abuse.ch threat intelligence for active malware distribution links, malware payloads, tags, and host reputation |
| `safe_browsing.py` | **Google Safe Browsing**: Checks target against Google Safe Browsing v4 API for malware, social engineering (phishing), and unwanted software |
| `cert_transparency.py` | **Certificate Transparency**: Searches crt.sh CT logs, calculates domain certificate longevity, tracks certificate churn (burst re-issuance), and discovers subdomains |
| `threat_graph.py` | **Threat Graph**: Constructs an entity graph connecting URLs, domains, IPs, nameservers, TLS certs, target brands, and threat indicators; outputs ASCII trees and interactive HTML |
| `history.py` | **Scan History**: SQLite database (`scan_history.db`) automatically recording all scans with timestamps, scores, verdicts, threats, and full JSON reports with CLI search & CSV/JSON export |
| `tls_check.py` | Real TLS handshake, certificate validity, expiration countdown, and self-signed detection |
| `dns_lookup.py` | DNS records resolution (A, AAAA, TXT, MX, NS) |
| `whois_lookup.py` | WHOIS domain age and registrar intelligence |
| `content_check.py` | Lightweight page content analysis for forms and script access |
| `virustotal.py` | VirusTotal v3 API multi-engine aggregation |
| `urlscan.py` | urlscan.io live sandboxed page inspection |
| `risk_score.py` | Aggregates all intelligence into a calibrated 0-100 risk score and verdict |
| `report.py` | Colorized terminal report formatter |
| `scan.py` | **Unified CLI Entry Point** |

## Setup

```bash
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in any API keys you wish to use:

```bash
cp .env.example .env
```

Available keys (all optional; scanner works offline and with free lookups):
- `VT_API_KEY`: VirusTotal API key (free tier at [virustotal.com](https://www.virustotal.com/gui/join-us))
- `URLSCAN_API_KEY`: urlscan.io API key (free tier at [urlscan.io](https://urlscan.io/user/signup))
- `SAFE_BROWSING_API_KEY`: Google Safe Browsing API key ([Google Cloud Console](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com))
- `URLHAUS_API_KEY`: abuse.ch URLhaus API key (optional, public lookups work without a key)

Verify detected keys anytime with:
```bash
python scan.py --check-keys
```

## Usage

### Basic Scan
```bash
python scan.py http://example.com
```

### Visual Threat Relationship Graph
```bash
# Print ASCII threat relationship tree directly in terminal
python scan.py http://paypaal.com --graph

# Export standalone interactive HTML graph (drag & zoom SOC UI)
python scan.py http://paypaal.com --graph-html threat.html

# Export Graphviz DOT format
python scan.py http://paypaal.com --graph-dot threat.dot
```

### Advanced Scan Options
```bash
python scan.py <url> --full-scan       # extended polling for VirusTotal (up to 60s) & urlscan.io (up to 45s)
python scan.py <url> --scan            # run live sandboxed urlscan.io inspection (~15-30s)
python scan.py <url> --json            # print raw structured JSON
python scan.py <url> --no-color        # disable ANSI colors (clean log output)
python scan.py <url> --no-redirect     # scan URL as-is without unmasking redirects
python scan.py <url> --no-vt-wait      # return immediately without waiting for fresh VT scan
python scan.py <url> --no-history      # skip recording this scan into SQLite database
```

### Scan History Management
Every scan is automatically stored in `scan_history.db`. Manage history directly from the CLI:

```bash
# List recent scans (default: 20)
python scan.py --history
python scan.py --history --history-limit 50

# Re-inspect a previous scan report without re-running network calls
python scan.py --history-show <id>

# Search scan history by URL, domain, or verdict
python scan.py --history-search paypal

# Export scan history to CSV or JSON
python scan.py --history-export scans.csv
python scan.py --history-export scans.json

# Clear all historical scan records
python scan.py --history-clear
```

## Running Unit Tests

Run the full automated test suite covering all 9 engines:
```bash
python tests.py
```
