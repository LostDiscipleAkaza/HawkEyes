# HawkEyes — Autonomous URL Threat Intelligence Engine

```
  ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗███████╗██╗   ██╗███████╗███████╗
  ██║  ██║██╔══██╗██║    ██║██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
  ███████║███████║██║ █╗ ██║█████═╝ █████╗   ╚████╔╝ █████╗  ███████╗
  ██╔══██║██╔══██║██║███╗██║██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
  ██║  ██║██║  ██║╚███╔███╔╝██║ ╚██╗███████╗   ██║   ███████╗███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚══════╝
  ┌─────────────────────────────────────────────────────────────────┐
  │  H A W K E Y E S :: Advanced URL Threat Intelligence Radar  │
  │      Autonomous Threat Hunting, Phishing & Fraud Engine       
  └─────────────────────────────────────────────────────────────────┘
```

**HawkEyes** is a modular, multi-engine cybersecurity tool designed for SOC analysts, security researchers, and developers. It unmasks cloaked links, dissects infrastructure, hunts phishing kits, and cross-references global threat intelligence feeds to compute a calibrated 0–100 risk score and entity relationship graph.

---

## ⚡ Quick Start: Interactive Mode

Simply start HawkEyes without arguments. It will display the console banner, prompt you for the target URL on a new line, and let you select the scan type interactively:

```bash
python scan.py
```

```text
  [ HawkEyes Interactive Threat Investigation Console ]

  Enter target URL (or 'h' for history, 'k' for keys, 'q' to exit):
  hawk-eyes> https://suspicious-login.xyz

  Select Scan Mode:
    [1] Standard Threat Scan    - Fast: Heuristics, DNS, TLS, WHOIS, CT, Phishing, URLhaus
    [2] Deep Security Scan      - Standard + ASCII Threat Graph + VT Wait (Recommended)
    [3] Comprehensive Sandbox   - Live sandboxed execution (urlscan.io) + Extended VT (~30-45s)
    [4] Threat Graph Visualizer - Standard scan + exports interactive visual HTML graph
    [5] Quick Recon             - Instant offline analysis (heuristics, typosquatting, homoglyphs)
  Select mode [1-5] (default: 2): 2

  [+] Launching HawkEyes inspection against: https://suspicious-login.xyz ...
```

---

## 🚀 Command-Line Usage (CI/CD & Scripting)

HawkEyes also supports direct non-interactive command-line execution for pipelines and automated triage:

```bash
# Standard terminal report
python scan.py https://example.com

# Print ASCII threat relationship tree in terminal
python scan.py https://paypaal.com --graph

# Export standalone interactive HTML visual graph (SOC UI)
python scan.py https://paypaal.com --graph-html threat.html

# Full-wait scan (waits up to 60s for fresh VirusTotal analysis)
python scan.py https://paypaal.com --full-scan

# Live sandboxed DOM execution via urlscan.io
python scan.py https://paypaal.com --scan

# Output raw JSON (for SIEM / ELK ingestion)
python scan.py https://example.com --json
```

---

## 📊 Pipeline Architecture

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

---

## 🛡️ Core Capabilities

| Module | Engine | Description |
|---|---|---|
| `redirect_resolver.py` | **Redirect Analysis** | Unmasks shorteners (bit.ly, t.co), follows client-side meta-refresh & JS redirects, logs per-hop HTTP status codes, flags open redirects and HTTPS-to-HTTP downgrades |
| `homoglyph.py` | **Homoglyph & IDN Detection** | Catches Punycode (`xn--`), confusable Unicode characters (Cyrillic, Greek, fullwidth), zero-width invisible characters, and mixed-script brand spoofing |
| `typosquatting.py` | **Typosquatting Engine** | Detects domain impersonation via omission, transposition, QWERTY substitution, repetition, combosquatting (`paypal-verify`), bitsquatting, and Levenshtein edit distance |
| `phishing_detector.py` | **Phishing Hunter** | Detects credential harvesting forms, known exfiltration endpoints (Discord webhooks, Telegram bots, Formspree), packed/obfuscated JS (`eval/unescape`), and urgency lures |
| `urlhaus.py` | **URLhaus Intelligence** | Queries abuse.ch threat intelligence for active malware distribution links, malware payloads, tags, and host reputation |
| `safe_browsing.py` | **Google Safe Browsing** | Checks targets against Google Safe Browsing v4 API for malware, social engineering (phishing), and unwanted software |
| `cert_transparency.py` | **Certificate Transparency** | Searches crt.sh CT logs, calculates domain certificate longevity, tracks certificate churn (burst re-issuance), and discovers subdomains |
| `threat_graph.py` | **Threat Relationship Graph** | Constructs an entity graph connecting URLs, domains, IPs, nameservers, TLS certs, target brands, and threat indicators; outputs ASCII trees and interactive HTML |
| `history.py` | **Scan History** | SQLite database (`scan_history.db`) automatically recording all scans with timestamps, scores, verdicts, threats, and full JSON reports with CLI search & CSV/JSON export |
| `tls_check.py` | **TLS Health** | Real TLS handshake, certificate validity, expiration countdown, and self-signed detection |
| `dns_lookup.py` | **DNS Enumeration** | DNS record resolution (A, AAAA, TXT, MX, NS) |
| `whois_lookup.py` | **WHOIS / RDAP** | WHOIS domain age and registrar intelligence |
| `risk_score.py` | **Risk Scoring Engine** | Aggregates all intelligence into a calibrated 0–100 risk score and verdict |
| `scan.py` | **HawkEyes CLI** | Unified interactive console and CLI runner |

---

## 🗄️ Scan History Management

Every scan is recorded automatically into local SQLite storage (`scan_history.db`). Manage history directly from the terminal:

```bash
# View recent scan history table
python scan.py --history
python scan.py --history 50

# Re-inspect a previous scan without re-running network queries
python scan.py --history-show <id>

# Search scan history by domain, URL, or verdict
python scan.py --history-search paypal

# Export scan history
python scan.py --history-export scans.csv
python scan.py --history-export scans.json

# Wipe all scan records
python scan.py --history-clear
```

---

## 🔑 API Keys (Optional)

HawkEyes works completely out-of-the-box offline and with free public endpoints. Adding API keys enables live multi-engine aggregation:

```bash
# Check key detection status
python scan.py --check-keys
```

Configure keys in `.env`:
```ini
VT_API_KEY=your_virustotal_api_key_here
URLSCAN_API_KEY=your_urlscan_api_key_here
SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key_here
URLHAUS_API_KEY=your_urlhaus_api_key_here
```

---

## 🧪 Unit Testing

Run the full automated test suite covering all engines:
```bash
python tests.py
```
