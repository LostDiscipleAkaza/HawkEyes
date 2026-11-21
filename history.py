"""
Stage 10: Scan History
SQLite-backed persistent history of URL scans. Allows reviewing past scans,
searching historical results, tracking threats over time, and exporting records.
"""
import csv
import json
import os
import sqlite3
from datetime import datetime, timezone

DB_FILENAME = "scan_history.db"


def _get_db_path(custom_path: str = None) -> str:
    if custom_path:
        return custom_path
    # Store next to this script by default
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, DB_FILENAME)


def init_db(db_path: str = None):
    path = _get_db_path(db_path)
    conn = sqlite3.connect(path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                input_url TEXT NOT NULL,
                final_url TEXT NOT NULL,
                domain TEXT,
                ip TEXT,
                risk_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                threats TEXT,
                raw_json TEXT NOT NULL
            )
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict)")
        conn.commit()
    finally:
        conn.close()


def _summarize_threats(result: dict) -> str:
    """Extracts high-level threat category badges from a scan result."""
    tags = []
    risk = result.get("risk", {})
    score = risk.get("score", 0)

    # URLhaus
    uh = result.get("urlhaus", {})
    if uh.get("listed"):
        tags.append("URLhaus Malware")
    elif uh.get("host_listed"):
        tags.append("URLhaus Host")

    # Safe Browsing
    sb = result.get("safe_browsing", {})
    if sb.get("matched"):
        types = sb.get("threat_types", [])
        if "SOCIAL_ENGINEERING" in types:
            tags.append("SafeBrowsing:Phish")
        elif "MALWARE" in types:
            tags.append("SafeBrowsing:Malware")
        else:
            tags.append("SafeBrowsing")

    # Phishing
    phish = result.get("phishing", {})
    if phish.get("is_phishing"):
        brand = phish.get("targeted_brand")
        tags.append(f"Phishing ({brand})" if brand else "Phishing")

    # Typosquatting
    typo = result.get("typosquatting", {})
    if typo.get("is_typosquat"):
        brand = typo.get("matched_brand")
        tags.append(f"Typosquat ({brand})" if brand else "Typosquat")

    # Homoglyph
    homo = result.get("homoglyph", {})
    if homo.get("has_homoglyphs"):
        if homo.get("is_mixed_script"):
            tags.append("Homoglyph:MixedScript")
        else:
            tags.append("Homoglyph")

    # Open redirect / downgrade
    redir = result.get("redirect", {})
    analysis = redir.get("analysis", {})
    if analysis.get("protocol_downgrade"):
        tags.append("HTTPS-Downgrade")
    if analysis.get("open_redirect_suspect"):
        tags.append("OpenRedirect")

    # VirusTotal
    vt = result.get("virustotal", {})
    if vt.get("malicious", 0) > 0:
        tags.append(f"VT:{vt['malicious']}")

    if not tags and score >= 40:
        tags.append("Heuristic Suspicious")

    return ", ".join(tags) if tags else "Clean"


def save_scan(result: dict, db_path: str = None) -> int:
    """
    Saves a scan result into SQLite history. Returns the newly inserted scan ID.
    """
    init_db(db_path)
    path = _get_db_path(db_path)

    parsed = result.get("parsed", {})
    risk = result.get("risk", {})
    dns_res = result.get("dns", {})

    input_url = result.get("input_url") or parsed.get("original_url") or ""
    final_url = parsed.get("original_url") or input_url
    domain = parsed.get("registered_domain") or parsed.get("hostname") or ""

    # Primary IP
    ip = ""
    a_records = dns_res.get("A", [])
    if a_records:
        ip = a_records[0]

    risk_score = int(risk.get("score", 0))
    verdict = risk.get("verdict", "Unknown")
    threats = _summarize_threats(result)
    raw_json = json.dumps(result, default=str)
    created_at = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (created_at, input_url, final_url, domain, ip, risk_score, verdict, threats, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (created_at, input_url, final_url, domain, ip, risk_score, verdict, threats, raw_json),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def list_scans(limit: int = 20, offset: int = 0, db_path: str = None) -> list:
    """Returns a list of recent scan summary records."""
    init_db(db_path)
    path = _get_db_path(db_path)

    conn = sqlite3.connect(path)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, created_at, input_url, final_url, domain, ip, risk_score, verdict, threats
            FROM scans
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_scan(scan_id: int, db_path: str = None) -> dict:
    """Retrieves a single scan record with full parsed JSON."""
    init_db(db_path)
    path = _get_db_path(db_path)

    conn = sqlite3.connect(path)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        res = dict(row)
        try:
            res["data"] = json.loads(res["raw_json"])
        except Exception:
            res["data"] = {}
        return res
    finally:
        conn.close()


def search_scans(query: str, limit: int = 20, db_path: str = None) -> list:
    """Searches scan history by URL, domain, verdict, or threat."""
    init_db(db_path)
    path = _get_db_path(db_path)
    q = f"%{query.strip()}%"

    conn = sqlite3.connect(path)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, created_at, input_url, final_url, domain, ip, risk_score, verdict, threats
            FROM scans
            WHERE input_url LIKE ? OR final_url LIKE ? OR domain LIKE ? OR verdict LIKE ? OR threats LIKE ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (q, q, q, q, q, limit),
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def clear_history(db_path: str = None) -> int:
    """Clears all scan history. Returns count of deleted records."""
    init_db(db_path)
    path = _get_db_path(db_path)

    conn = sqlite3.connect(path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans")
        count = cursor.fetchone()[0]
        cursor.execute("DELETE FROM scans")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='scans'")
        conn.commit()
        return count
    finally:
        conn.close()


def export_history(output_file: str, fmt: str = "json", db_path: str = None) -> int:
    """Exports history to a file in json or csv format."""
    scans = list_scans(limit=10000, db_path=db_path)
    if fmt.lower() == "csv":
        if not scans:
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["id", "created_at", "input_url", "final_url", "domain", "ip", "risk_score", "verdict", "threats"])
            return 0
        keys = ["id", "created_at", "input_url", "final_url", "domain", "ip", "risk_score", "verdict", "threats"]
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for s in scans:
                writer.writerow({k: s.get(k) for k in keys})
    else:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(scans, f, indent=2, default=str)
    return len(scans)


def format_history_table(scans: list, use_color: bool = True) -> str:
    """Renders a beautiful CLI table for past scans."""
    if not scans:
        return "  No scan history found."

    RESET = "\033[0m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    GRAY = "\033[90m" if use_color else ""
    RED = "\033[91m" if use_color else ""
    ORANGE = "\033[38;5;208m" if use_color else ""
    YELLOW = "\033[93m" if use_color else ""
    GREEN = "\033[92m" if use_color else ""

    def _color_for_score(score: int, verdict: str) -> str:
        if not use_color:
            return ""
        if score >= 70 or verdict == "High Risk":
            return RED
        if score >= 40 or verdict == "Medium Risk":
            return ORANGE
        if score >= 15 or verdict == "Low Risk":
            return YELLOW
        return GREEN

    lines = []
    lines.append(f"{BOLD}{'ID':<5} {'Date (UTC)':<17} {'Score':<7} {'Verdict':<15} {'Domain / URL':<32} {'Threats'}{RESET}")
    lines.append(GRAY + "─" * 100 + RESET)

    for s in scans:
        sid = str(s["id"])
        # Format date as YYYY-MM-DD HH:MM
        raw_dt = s.get("created_at") or ""
        dt_str = raw_dt[:16].replace("T", " ") if raw_dt else "—"

        score = s.get("risk_score", 0)
        verdict = s.get("verdict", "Unknown")
        c = _color_for_score(score, verdict)
        score_str = f"{c}{score:>3}/100{RESET}"
        verdict_str = f"{c}{verdict:<15}{RESET}"

        target = s.get("domain") or s.get("input_url") or "—"
        if len(target) > 30:
            target = target[:27] + "..."

        threats = s.get("threats") or "Clean"
        if len(threats) > 32:
            threats = threats[:29] + "..."

        lines.append(f"{sid:<5} {dt_str:<17} {score_str} {verdict_str} {target:<32} {GRAY}{threats}{RESET}")

    lines.append(GRAY + "─" * 100 + RESET)
    lines.append(f"  {GRAY}Total records shown: {len(scans)}{RESET}")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--clear":
        n = clear_history()
        print(f"Cleared {n} scan records.")
    else:
        results = list_scans(limit=25)
        print(format_history_table(results))
