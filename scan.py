#!/usr/bin/env python3
"""
CLI entry point for HawkEyes.
Autonomous URL Threat Intelligence, Phishing Detection & Risk Scoring Engine.

Usage:
    python scan.py                           # launch HawkEyes interactive console
    python scan.py <url>                     # quick scan with terminal report
    python scan.py <url> --graph             # also print the ASCII Threat Relationship Graph
    python scan.py <url> --graph-html file   # export interactive HTML visual threat graph
    python scan.py <url> --full-scan         # extended analysis: polls VT (up to 60s) & urlscan.io (up to 45s)
    python scan.py <url> --scan              # also run live urlscan.io (~30s)
    python scan.py <url> --json              # raw JSON instead of formatted report
    python scan.py <url> --no-color          # plain text, no ANSI colors
    python scan.py <url> --no-redirect       # scan the URL as-is, don't unmask shorteners
    python scan.py <url> --no-history        # don't save scan to local database history

Scan History Management:
    python scan.py --history [N]             # list recent N scans (default: 20)
    python scan.py --history-show <id>       # view full report for a previous scan
    python scan.py --history-search <query>  # search past scans by URL, domain, or verdict
    python scan.py --history-export out.csv  # export history to CSV or JSON
    python scan.py --history-clear           # wipe all scan history

API Keys:
    python scan.py --check-keys              # inspect status of VT, URLScan, SafeBrowsing, URLhaus keys
"""
import argparse
import json
import os
import sys

# Ensure UTF-8 output on Windows consoles/terminals
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def print_banner(use_color: bool = True):
    CYAN = "\033[96m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    GRAY = "\033[90m" if use_color else ""
    GREEN = "\033[92m" if use_color else ""
    YELLOW = "\033[93m" if use_color else ""
    RESET = "\033[0m" if use_color else ""

    banner = f"""{CYAN}{BOLD}
  ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗███████╗██╗   ██╗███████╗███████╗
  ██║  ██║██╔══██╗██║    ██║██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
  ███████║███████║██║ █╗ ██║█████═╝ █████╗   ╚████╔╝ █████╗  ███████╗
  ██╔══██║██╔══██║██║███╗██║██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
  ██║  ██║██║  ██║╚███╔███╔╝██║ ╚██╗███████╗   ██║   ███████╗███████║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚══════╝{RESET}
  {GRAY}┌─────────────────────────────────────────────────────────────────┐{RESET}
  {GRAY}│{RESET}  {YELLOW}H A W K E Y E S{RESET} {GRAY}:: Advanced URL Threat Intelligence Radar{RESET}  {GRAY}│{RESET}
  {GRAY}│{RESET}  {GREEN}Autonomous Threat Hunting, Phishing & Fraud Engine{RESET}       {GRAY}│{RESET}
  {GRAY}└─────────────────────────────────────────────────────────────────┘{RESET}
"""
    print(banner)


def _mask(key: str) -> str:
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}...{key[-4:]} ({len(key)} chars)"


def check_keys():
    expectations = {
        "VT_API_KEY": (64, "VirusTotal API Key (virustotal.com)"),
        "URLSCAN_API_KEY": (36, "urlscan.io API Key (urlscan.io)"),
        "SAFE_BROWSING_API_KEY": (39, "Google Safe Browsing API Key (console.cloud.google.com)"),
        "URLHAUS_API_KEY": (0, "URLhaus API Key (optional, abuse.ch)"),
    }

    print("Checking which threat intelligence API keys HawkEyes can see:\n")
    for name, (expected_len, desc) in expectations.items():
        value = os.environ.get(name, "")
        if not value:
            opt_tag = " (OPTIONAL)" if expected_len == 0 or name == "SAFE_BROWSING_API_KEY" else ""
            print(f"  {name:<24} MISSING{opt_tag} -> not configured in environment or .env ({desc})")
            continue

        print(f"  {name:<24} FOUND   -> {_mask(value)} ({desc})")
        has_junk = value != value.strip() or '"' in value or "'" in value
        if has_junk:
            print("                           ⚠ contains quotes or whitespace — remove them from .env")
        elif expected_len > 0 and abs(len(value) - expected_len) > 5:
            print(f"                           ⚠ expected ~{expected_len} characters, got {len(value)}")

    print(
        "\nNote: HawkEyes works offline and with free public endpoints without keys,"
        "\nbut setting VT_API_KEY and SAFE_BROWSING_API_KEY unlocks full multi-engine coverage."
    )


def handle_history_commands(args) -> bool:
    """Executes history CLI commands if requested. Returns True if a history command was handled."""
    from history import (
        clear_history,
        export_history,
        format_history_table,
        get_scan,
        list_scans,
        search_scans,
    )
    from report import format_report, format_report_plain

    is_tty = sys.stdout.isatty() and not args.no_color

    if args.history_clear:
        count = clear_history()
        print(f"Scan history cleared ({count} records deleted).")
        return True

    if args.history_export:
        fmt = "csv" if args.history_export.lower().endswith(".csv") else "json"
        count = export_history(args.history_export, fmt=fmt)
        print(f"Exported {count} scan record(s) to {args.history_export}")
        return True

    if args.history_search:
        results = search_scans(args.history_search, limit=args.history_limit or 25)
        print(f"\nSearch results for '{args.history_search}':\n")
        print(format_history_table(results, use_color=is_tty))
        return True

    if args.history_show is not None:
        rec = get_scan(args.history_show)
        if not rec:
            print(f"Scan #{args.history_show} not found in history.\n")
            recent = list_scans(limit=10)
            if recent:
                print("Available recent scans in database:")
                print(format_history_table(recent, use_color=is_tty))
            else:
                print("The database currently has no saved scans.")
            sys.exit(1)
        data = rec.get("data", {})
        if args.json:
            print(json.dumps(data, indent=2, default=str))
        elif is_tty:
            print(format_report(data))
        else:
            print(format_report_plain(data))
        return True

    if args.history is not None or args.history_limit is not None:
        limit = args.history if (isinstance(args.history, int) and args.history > 0) else (args.history_limit or 20)
        results = list_scans(limit=limit)
        print(f"\nRecent Scan History (last {len(results)} scans):\n")
        print(format_history_table(results, use_color=is_tty))
        print(f"\nTip: Run 'python scan.py --history-show <id>' to inspect full details for any scan.\n")
        return True

    return False


def run_interactive(args):
    """Interactive CLI investigation console launched when scan.py is called with no arguments."""
    is_tty = sys.stdout.isatty() and not args.no_color
    print_banner(use_color=is_tty)
    print("  [ HawkEyes Interactive Threat Investigation Console ]\n")

    while True:
        try:
            print("  Enter target URL (or 'h' for history, 'k' for keys, 'q' to exit):")
            url_input = input("  hawk-eyes> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Exiting HawkEyes.")
            break

        if not url_input:
            continue
        if url_input.lower() in ("q", "quit", "exit"):
            print("  Exiting HawkEyes.")
            break
        if url_input.lower() in ("h", "history"):
            from history import list_scans, format_history_table
            scans = list_scans(limit=args.history_limit or 20)
            print(f"\nRecent Scan History (last {len(scans)} scans):\n")
            print(format_history_table(scans, use_color=is_tty))
            print()
            continue
        if url_input.lower() in ("k", "keys"):
            check_keys()
            print()
            continue

        # Format URL scheme if missing
        clean_url = url_input
        if not clean_url.startswith(("http://", "https://")):
            clean_url = "https://" + clean_url

        print(f"\n  Target: {clean_url}")
        print("  Select Scan Mode:")
        print("    [1] Standard Threat Scan    - Fast: Heuristics, DNS, TLS, WHOIS, CT, Phishing, URLhaus")
        print("    [2] Deep Security Scan      - Standard + ASCII Threat Graph + VT Wait (Recommended)")
        print("    [3] Comprehensive Sandbox   - Live sandboxed execution (urlscan.io) + Extended VT (~30-45s)")
        print("    [4] Threat Graph Visualizer - Standard scan + exports interactive visual HTML graph")
        print("    [5] Quick Recon             - Instant offline analysis (heuristics, typosquatting, homoglyphs)")

        try:
            mode_choice = input("  Select mode [1-5] (default: 2): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Exiting HawkEyes.")
            break

        if not mode_choice:
            mode_choice = "2"

        use_urlscan = False
        follow_redirects = True
        vt_max_wait = 25.0
        urlscan_max_wait = 30.0
        show_graph = False
        export_html = None

        if mode_choice == "1":
            vt_max_wait = 0.0
            show_graph = False
        elif mode_choice == "2":
            vt_max_wait = 25.0
            show_graph = True
        elif mode_choice == "3":
            use_urlscan = True
            vt_max_wait = 60.0
            urlscan_max_wait = 45.0
            show_graph = True
        elif mode_choice == "4":
            vt_max_wait = 25.0
            show_graph = True
            export_html = "hawkeyes_threat_graph.html"
        elif mode_choice == "5":
            vt_max_wait = 0.0
            show_graph = False
            follow_redirects = False
        else:
            vt_max_wait = 25.0
            show_graph = True

        print(f"\n  [+] Launching HawkEyes inspection against: {clean_url} ...\n")
        from pipeline import run_pipeline
        from report import format_report, format_report_plain
        from threat_graph import format_threat_graph_ascii, export_threat_graph_html
        from history import save_scan

        result = run_pipeline(
            clean_url,
            use_urlscan=use_urlscan,
            follow_redirects=follow_redirects,
            vt_max_wait=vt_max_wait,
            urlscan_max_wait=urlscan_max_wait,
        )

        sid = None
        if not args.no_history:
            try:
                sid = save_scan(result)
            except Exception:
                pass

        report_text = format_report(result) if is_tty else format_report_plain(result)
        print(report_text)

        if show_graph:
            tg = result.get("threat_graph", {})
            print()
            print(format_threat_graph_ascii(tg, use_color=is_tty))

        if export_html:
            export_threat_graph_html(result.get("threat_graph", {}), export_html)
            print(f"\n  [+] Exported interactive visual threat graph to: {export_html}")

        if sid:
            print(f"\n  [i] Scan result recorded to database as Scan #{sid}")

        print("\n  " + "─" * 68)
        try:
            another = input("  Investigate another URL? (y/N) [N]: ").strip().lower()
            print()
            if another not in ("y", "yes"):
                print("  Thank you for using HawkEyes.\n")
                break
        except (KeyboardInterrupt, EOFError):
            print("\n  Exiting HawkEyes.\n")
            break


def main():
    parser = argparse.ArgumentParser(description="HawkEyes — Autonomous URL Threat Intelligence & Phishing Hunter.")
    parser.add_argument("url", nargs="?", help="The URL to scan (omit to launch interactive console)")

    # API Keys & History commands
    parser.add_argument("--check-keys", action="store_true", help="Show detected API keys and exit")
    parser.add_argument(
        "--history",
        nargs="?",
        const=20,
        type=int,
        default=None,
        metavar="LIMIT",
        help="Display recent scan history (optional: number of entries, e.g. --history 10)",
    )
    parser.add_argument("--history-limit", type=int, default=None, help="Number of history rows to list")
    parser.add_argument("--history-show", type=int, metavar="ID", help="Show full report for a previous scan ID")
    parser.add_argument("--history-search", type=str, metavar="QUERY", help="Search history by URL, domain, or verdict")
    parser.add_argument("--history-clear", action="store_true", help="Wipe all scan history records")
    parser.add_argument("--history-export", type=str, metavar="FILE", help="Export history to CSV or JSON file")
    parser.add_argument("--no-history", action="store_true", help="Skip saving this scan to local database")

    # Threat Graph options
    parser.add_argument("--graph", action="store_true", help="Display ASCII Threat Relationship Graph in report")
    parser.add_argument("--graph-html", type=str, metavar="FILE", help="Export interactive visual HTML threat graph")
    parser.add_argument("--graph-dot", type=str, metavar="FILE", help="Export Graphviz DOT graph to file")
    parser.add_argument("--graph-json", action="store_true", help="Output Threat Graph nodes and edges in JSON")

    # Pipeline options
    parser.add_argument("--full-scan", action="store_true", help="Comprehensive scan with extended VT and urlscan polling")
    parser.add_argument("--scan", action="store_true", help="Also run a live urlscan.io scan")
    parser.add_argument("--json", action="store_true", help="Print raw JSON instead of formatted report")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in the report")
    parser.add_argument("--no-redirect", action="store_true", help="Don't follow redirects — scan URL as-is")
    parser.add_argument("--no-vt-wait", action="store_true", help="Don't wait for freshly submitted VirusTotal scan")
    parser.add_argument("--vt-wait", type=float, default=25.0, help="Seconds to wait for VirusTotal scan (default: 25)")
    parser.add_argument("--urlscan-wait", type=float, default=30.0, help="Seconds to wait for urlscan.io (default: 30)")

    args = parser.parse_args()

    if args.check_keys:
        check_keys()
        return

    if handle_history_commands(args):
        return

    # If no URL is given, launch the interactive HawkEyes console
    if not args.url:
        run_interactive(args)
        return

    from pipeline import run_pipeline
    from report import format_report, format_report_plain
    from threat_graph import export_threat_graph_dot, export_threat_graph_html, format_threat_graph_ascii
    from history import save_scan

    use_urlscan = args.scan or args.full_scan
    vt_max_wait = 0.0 if args.no_vt_wait else (60.0 if args.full_scan else args.vt_wait)
    urlscan_max_wait = 45.0 if args.full_scan else args.urlscan_wait

    result = run_pipeline(
        args.url,
        use_urlscan=use_urlscan,
        follow_redirects=not args.no_redirect,
        vt_max_wait=vt_max_wait,
        urlscan_max_wait=urlscan_max_wait,
    )

    # Automatically save scan to history database
    if not args.no_history:
        try:
            save_scan(result)
        except Exception:
            pass

    # Threat graph file exports
    if args.graph_html:
        export_threat_graph_html(result.get("threat_graph", {}), args.graph_html)
        print(f"Exported interactive visual threat graph to: {args.graph_html}")

    if args.graph_dot:
        dot_code = export_threat_graph_dot(result.get("threat_graph", {}))
        with open(args.graph_dot, "w", encoding="utf-8") as f:
            f.write(dot_code)
        print(f"Exported Graphviz DOT graph to: {args.graph_dot}")

    if args.graph_json:
        print(json.dumps(result.get("threat_graph", {}), indent=2, default=str))
        return

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    is_tty = sys.stdout.isatty() and not args.no_color

    # Print decorative banner for terminal users
    if is_tty:
        print_banner(use_color=True)

    if is_tty:
        report_text = format_report(result)
    else:
        report_text = format_report_plain(result)

    print(report_text)

    # Optional ASCII Threat Graph rendering in terminal
    if args.graph:
        tg = result.get("threat_graph", {})
        print()
        print(format_threat_graph_ascii(tg, use_color=is_tty))

    # Exit code reflects risk
    sys.exit(0 if result["risk"]["score"] < 40 else 1)


if __name__ == "__main__":
    main()
