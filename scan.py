#!/usr/bin/env python3
"""
CLI entry point. Run a scan and print the report straight to the terminal.

Usage:
    python scan.py <url>
    python scan.py <url> --full-scan     # extended analysis: polls VT (up to 60s) and urlscan.io (up to 45s)
    python scan.py <url> --scan          # also run live urlscan.io (~30s)
    python scan.py <url> --json          # raw JSON instead of formatted report
    python scan.py <url> --no-color      # plain text, no ANSI colors
    python scan.py <url> --no-redirect   # scan the URL as-is, don't unmask shorteners
    python scan.py <url> --no-vt-wait    # don't wait for a fresh VT scan to complete (instant, may show "pending")
    python scan.py <url> --vt-wait 60    # wait up to 60s for VT instead of the default 25s
    python scan.py <url> --urlscan-wait 45 # wait up to 45s for urlscan.io
    python scan.py --check-keys          # show whether VT_API_KEY / URLSCAN_API_KEY are detected (no url needed)
"""
import argparse
import json
import os
import sys

# Ensure UTF-8 output on Windows consoles/terminals so box-drawing characters don't raise UnicodeEncodeError
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
# pipeline/report are imported lazily inside main() below, so --check-keys
# still works even if the rest of requirements.txt isn't installed yet.


def _mask(key: str) -> str:
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}...{key[-4:]} ({len(key)} chars)"


def check_keys():
    # VT keys are always exactly 64 hex chars; urlscan.io keys are UUIDs (36 chars,
    # with hyphens). If the length is off, the key almost certainly has stray
    # whitespace/quotes/newlines stuck to it from a copy-paste.
    expectations = {"VT_API_KEY": 64, "URLSCAN_API_KEY": 36}

    print("Checking which API keys this script can actually see:\n")
    for name, expected_len in expectations.items():
        value = os.environ.get(name, "")
        if not value:
            print(f"  {name:<18} MISSING -> not set in this shell or in a .env file next to scan.py")
            continue

        print(f"  {name:<18} FOUND   -> {_mask(value)}")
        has_junk = value != value.strip() or '"' in value or "'" in value
        if has_junk:
            print(f"                       ⚠ contains leading/trailing whitespace or quote characters — remove them")
        elif len(value) != expected_len:
            print(
                f"                       ⚠ expected {expected_len} characters, got {len(value)} — "
                f"this usually means the key got truncated or extra characters got pasted in"
            )

    print(
        "\nNote: the names must match EXACTLY - e.g. 'URLSCANNER_API_KEY' will NOT be picked up, "
        "it must be 'URLSCAN_API_KEY'. Easiest fix: copy .env.example to .env in this folder and "
        "fill in the values there, with no quotes around the key — no shell export needed."
    )


def main():
    parser = argparse.ArgumentParser(description="Scan a URL and print a risk report to the terminal.")
    parser.add_argument("url", nargs="?", help="The URL to scan")
    parser.add_argument(
        "--check-keys", action="store_true",
        help="Show which API keys are detected in this environment, then exit"
    )
    parser.add_argument(
        "--full-scan", action="store_true",
        help="Run comprehensive scan with extended polling for VirusTotal (up to 60s) and urlscan.io (up to 45s)"
    )
    parser.add_argument("--scan", action="store_true", help="Also run a live urlscan.io scan")
    parser.add_argument("--json", action="store_true", help="Print raw JSON instead of a formatted report")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in the report")
    parser.add_argument(
        "--no-redirect", action="store_true",
        help="Don't follow redirects — scan the given URL exactly as-is"
    )
    parser.add_argument(
        "--no-vt-wait", action="store_true",
        help="Don't wait for a freshly-submitted VirusTotal scan to finish"
    )
    parser.add_argument(
        "--vt-wait", type=float, default=25.0,
        help="Seconds to wait for a fresh VirusTotal scan to complete (default: 25)"
    )
    parser.add_argument(
        "--urlscan-wait", type=float, default=30.0,
        help="Seconds to wait for a urlscan.io live scan to complete (default: 30)"
    )
    args = parser.parse_args()

    if args.check_keys:
        check_keys()
        return

    if not args.url:
        parser.error("the following arguments are required: url (unless using --check-keys)")

    from pipeline import run_pipeline
    from report import format_report, format_report_plain

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

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    is_tty = sys.stdout.isatty()
    if args.no_color or not is_tty:
        print(format_report_plain(result))
    else:
        print(format_report(result))

    # Exit code reflects risk, handy for scripting/CI use
    sys.exit(0 if result["risk"]["score"] < 40 else 1)


if __name__ == "__main__":
    main()
