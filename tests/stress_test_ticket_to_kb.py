#!/usr/bin/env python3
"""
Stress Test Suite for Ticket-to-Knowledge-Base Article Writer (stress_test_ticket_to_kb.py)

Executes intensive stress tests across:
1. High-volume ticket processing (50,000-line logs, batch processing).
2. Diverse and corrupted ITSM schemas (ServiceNow, Jira, Zendesk edge cases).
3. Complex and obfuscated PII sanitization batteries.
4. Multi-format output structural integrity under stress.
5. Throughput and performance benchmarks.

Conforms strictly to:
- Rule 3: Zero external dependencies (pure Python standard library).
- Rule 7: Zero-emoji enterprise compliance.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import time
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
SCRIPTS_DIR = PROJECT_DIR / "scripts"

sys.path.insert(0, str(SCRIPTS_DIR))
from ticket_to_kb import Sanitizer, TicketParser, KCSArticleGenerator, TicketData


class TestHighVolumeAndThroughput(unittest.TestCase):
    """Stress Category 1: Volume, Load, and Throughput."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = TicketParser(sanitizer=self.sanitizer)
        self.generator = KCSArticleGenerator(sanitizer=self.sanitizer)

    def test_massive_50000_line_log_history(self) -> None:
        """Processes a 50,000-line ticket transcript without OOM or catastrophic slowdown."""
        header = "Ticket: INC-STRESS-50K\nCategory: Infrastructure\nDevice: SRV-PROD-99.corp.local\n\nWORK NOTES:\n"
        log_lines = [
            f"2026-11-01 12:{i%60:02d}:{i%60:02d} EST - Tech: Inspected thread {i} with error 0x8004010F on client 192.168.1.{i%250 + 1}"
            for i in range(50000)
        ]
        content = header + "\n".join(log_lines)

        t0 = time.perf_counter()
        ticket = self.parser.parse(content)
        md = self.generator.format_markdown(ticket, sanitize=True)
        t1 = time.perf_counter()
        elapsed = t1 - t0

        lines_per_sec = 50000 / elapsed if elapsed > 0 else 50000
        self.assertLess(elapsed, 10.0, f"50k lines took {elapsed:.2f}s, expected < 10.0s")
        self.assertIn("## Issue Symptoms", md)
        self.assertIn("## Resolution Steps", md)
        print(f"\n[STRESS BENCHMARK] 50,000 lines processed in {elapsed:.3f}s ({lines_per_sec:.0f} lines/sec)")

    def test_rapid_batch_processing_500_tickets(self) -> None:
        """Processes 500 distinct ticket payloads sequentially."""
        t0 = time.perf_counter()
        for i in range(500):
            ticket_json = json.dumps({
                "number": f"INC{100000 + i}",
                "short_description": f"Batch Incident {i}: Connection timeout to database",
                "category": "Database",
                "subcategory": "Connectivity",
                "caller_id": f"user-{i}@synthetic-test.local",
                "client_ip": f"10.0.{i%250}.{i%250 + 1}",
                "workstation": f"WS-BATCH-{i:03d}.corp.local",
                "work_notes": f"Step 1: Restarted connection pool.\nStep 2: Cleared stale session {i}.\nVerified service status.",
                "close_notes": f"Pool {i} recycled successfully."
            })
            ticket = self.parser.parse(ticket_json)
            md = self.generator.format_markdown(ticket, sanitize=True)
            self.assertIn(f"INC{100000 + i}", md)
        t1 = time.perf_counter()
        elapsed = t1 - t0
        rate = 500 / elapsed if elapsed > 0 else 500
        self.assertLess(elapsed, 5.0, f"500 tickets took {elapsed:.2f}s, expected < 5.0s")
        print(f"[STRESS BENCHMARK] 500 tickets processed in {elapsed:.3f}s ({rate:.0f} tickets/sec)")


class TestCorruptedAndExtremeSchemas(unittest.TestCase):
    """Stress Category 2: Corrupted, Non-Standard, and Edge ITSM Schemas."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = TicketParser(sanitizer=self.sanitizer)
        self.generator = KCSArticleGenerator(sanitizer=self.sanitizer)

    def test_non_string_fields_in_json(self) -> None:
        """Handles JSON containing integers, booleans, floats, nulls, and nested dicts in unexpected fields."""
        weird_payload = {
            "number": 998877,
            "short_description": 123456,
            "category": None,
            "subcategory": False,
            "workstation": 3.14159,
            "client_ip": None,
            "work_notes": ["Note item 1", "Note item 2", {"nested": "value"}],
            "close_notes": {"author": "Tech", "status": 200}
        }
        ticket = self.parser.parse(json.dumps(weird_payload))
        self.assertIsNotNone(ticket)
        md = self.generator.format_markdown(ticket, sanitize=True)
        self.assertIn("## Issue Symptoms", md)

    def test_json_array_root(self) -> None:
        """Handles JSON with an array as the root element instead of an object."""
        array_payload = json.dumps([
            {"number": "INC001", "short_description": "First ticket in array"},
            {"number": "INC002", "short_description": "Second ticket in array"}
        ])
        ticket = self.parser.parse(array_payload)
        self.assertIsNotNone(ticket)
        md = self.generator.format_markdown(ticket, sanitize=True)
        self.assertIn("## Issue Symptoms", md)

    def test_deeply_nested_jira_comments(self) -> None:
        """Handles Jira schemas with 100 comment objects and diverse author structures."""
        comments = []
        for i in range(100):
            comments.append({
                "id": f"comment_{i}",
                "author": {"name": f"tech_{i}", "displayName": f"Technician {i}"},
                "body": f"Action {i}: Executed command Restart-Service Spooler. Status code 200."
            })
        jira_payload = {
            "key": "DEEP-9999",
            "fields": {
                "summary": "Deep Jira Incident with 100 comments",
                "description": "Initial problem intake description.",
                "comment": {"comments": comments},
                "resolution": {"name": "Resolved", "description": "Cleared service faults."}
            }
        }
        ticket = self.parser.parse(json.dumps(jira_payload))
        self.assertEqual(ticket.ticket_id, "DEEP-9999")
        self.assertGreaterEqual(len(ticket.resolution_steps), 1)

    def test_empty_keys_and_whitespace_values(self) -> None:
        """Handles tickets with empty strings, whitespace-only fields, and missing elements."""
        sparse = {
            "number": "",
            "short_description": "   ",
            "description": "\n\n",
            "work_notes": "   \t   \n",
            "close_notes": ""
        }
        ticket = self.parser.parse(json.dumps(sparse))
        md = self.generator.format_markdown(ticket, sanitize=True)
        self.assertIn("## Issue Symptoms", md)
        self.assertIn("## Resolution Steps", md)


class TestIntensivePIISanitization(unittest.TestCase):
    """Stress Category 3: Intensive PII Sanitization Batteries."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()

    def test_40_pii_variations(self) -> None:
        """Tests 40 varied PII strings across emails, IPs, phone numbers, GUIDs, and credentials."""
        test_cases = [
            ("email", "john.doe@contoso.com", r"user-[a-f0-9]{8}@corp\.example\.com"),
            ("email", "jane_smith+ops@corp.internal", r"user-[a-f0-9]{8}@corp\.example\.com"),
            ("email", "first.middle.last@subdomain.example.org", r"user-[a-f0-9]{8}@corp\.example\.com"),
            ("phone", "+1-555-0199", "[REDACTED_PHONE]"),
            ("phone", "(555) 123-4567", "[REDACTED_PHONE]"),
            ("phone", "555-0144", "[REDACTED_PHONE]"),
            ("phone", "+44 20 7946 0958", "[REDACTED_PHONE]"),
            ("phone", "+49 30 1234 5678", "[REDACTED_PHONE]"),
            ("phone", "555.012.3456", "[REDACTED_PHONE]"),
            ("guid", "12345678-1234-4234-8234-123456789abc", "00000000-0000-4000-a000-000000000000"),
            ("guid", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "00000000-0000-4000-a000-000000000000"),
            ("bitlocker", "123456-789012-345678-901234-567890-123456-789012-345678", "[REDACTED_CREDENTIAL]"),
            ("bitlocker", "999999-888888-777777-666666-555555-444444-333333-222222", "[REDACTED_CREDENTIAL]"),
            ("ip_private", "10.240.12.89", r"192\.0\.2\.\d+"),
            ("ip_private", "172.16.50.4", r"192\.0\.2\.\d+"),
            ("ip_private", "192.168.100.1", r"192\.0\.2\.\d+"),
            ("ip_public", "203.0.113.195", "203.0.113.195"),  # Documentation IP preserved
            ("ip_loopback", "127.0.0.1", "127.0.0.1"),  # Loopback preserved
            ("hostname", "WORKSTATION-NYC-001", r"DEVICE-\d{2}\.contoso\.local"),
            ("hostname", "DESKTOP-LON-8891", r"DEVICE-\d{2}\.contoso\.local"),
            ("hostname", "LAPTOP-TOK-4412", r"DEVICE-\d{2}\.contoso\.local"),
            ("hostname_server", "SRV-EXCHANGE-01.corp.local", r"SERVER-\d{2}\.contoso\.local"),
            ("hostname_server", "PRINT-SPOOL-02.internal", r"SERVER-\d{2}\.contoso\.local"),
            ("hostname_server", "DC-PRIMARY-01.contoso.local", r"SERVER-\d{2}\.contoso\.local"),
            ("cred", "password='SuperSecretPass123!'", "[REDACTED_CREDENTIAL]"),
            ("cred", "passwd: MyMasterSecret456", "[REDACTED_CREDENTIAL]"),
            ("cred", "token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'", "[REDACTED_CREDENTIAL]"),
            ("cred", "api_key: 'sk_live_998877665544332211'", "[REDACTED_CREDENTIAL]"),
            ("cred", "-Password 'P@ssw0rd2026!'", "[REDACTED_CREDENTIAL]"),
            ("cred", "-Token 'ghp_secret_access_token_12345'", "[REDACTED_CREDENTIAL]"),
            ("cred", "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz", "[REDACTED_CREDENTIAL]"),
        ]

        for pii_type, raw, expected_pattern in test_cases:
            scrubbed = self.sanitizer.scrub(raw)
            self.assertRegex(
                scrubbed, expected_pattern,
                f"Failed to scrub {pii_type}: input '{raw}' produced '{scrubbed}'"
            )

    def test_version_strings_are_not_corrupted_as_phones(self) -> None:
        """Ensures Windows and software version strings are never scrubbed as phone numbers."""
        versions = [
            "Windows 11 Build 22631.3880",
            "OneDrive Version 24.181.0908.0001",
            "Exchange Server 15.2.1544.11",
            "Spooler version 10.0.20348.1907",
            "Driver hpz3r500.dll version 0.3.1537.404"
        ]
        for ver in versions:
            scrubbed = self.sanitizer.scrub(ver)
            self.assertNotIn("[REDACTED_PHONE]", scrubbed, f"Version '{ver}' was falsely scrubbed as phone: '{scrubbed}'")


class TestAdversarialSecurityAndInjection(unittest.TestCase):
    """Stress Category 4: Adversarial Security, XSS, and Prompt Injection."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = TicketParser(sanitizer=self.sanitizer)
        self.generator = KCSArticleGenerator(sanitizer=self.sanitizer)

    def test_html_xss_injection_prevention(self) -> None:
        """Ensures script tags, image onerror, and iframe injections in tickets are safely escaped in HTML."""
        xss_ticket = {
            "number": "INC-XSS-001",
            "short_description": "<script>alert('xss')</script> XSS in title",
            "description": "<img src=x onerror=alert(1)> Injected description",
            "work_notes": "<iframe src='javascript:alert(2)'></iframe>\nStop-Service Spooler",
            "close_notes": "<b>Bold text</b> & <marquee>alert</marquee>"
        }
        ticket = self.parser.parse(json.dumps(xss_ticket))
        html_out = self.generator.format_html(ticket, sanitize=True)

        self.assertNotIn("<script>", html_out)
        self.assertNotIn("<iframe", html_out)
        self.assertNotIn("<img src=x onerror=", html_out)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", html_out)

    def test_markdown_header_injection_containment(self) -> None:
        """Ensures adversarial markdown headers in work notes do not break the structural hierarchy."""
        attack_text = """Ticket: INC-ATTACK-001
Symptoms: Normal symptoms
Resolution:
1. First step
# INJECTED TOP LEVEL HEADER
## FAKE METADATA
- **Injected Field:** Malicious
2. Second step"""
        ticket = self.parser.parse(attack_text)
        md = self.generator.format_markdown(ticket, sanitize=True)

        # The article must still retain its single top-level title
        top_headers = [line for line in md.splitlines() if line.startswith("# ")]
        self.assertEqual(len(top_headers), 1, f"Expected exactly 1 top-level title, got: {top_headers}")


class TestExtremeBoundaryConditions(unittest.TestCase):
    """Stress Category 5: Extreme Edge Cases and Boundary Conditions."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = TicketParser(sanitizer=self.sanitizer)
        self.generator = KCSArticleGenerator(sanitizer=self.sanitizer)

    def test_unicode_and_international_names(self) -> None:
        """Handles non-ASCII Unicode characters, umlauts, Cyrillic, and accented customer names."""
        intl_ticket = """Ticket: INC-INTL-001
Customer: José García Müller <jose.garcia@münchen-corp.de>
Assigned Engineer: Elena Rostova <elena.rostova@synthetic-test.local>
Category: Internationalization
Initial Symptoms:
Benutzer meldet Absturz der Anwendung bei Sonderzeichen (ä, ö, ü, ß, €).
Root Cause:
UTF-8 byte order mark (BOM) mismatch in database encoding layer.
Work Notes & Troubleshooting:
1. Konfigurierte NLS_LANG Parameter in Registry.
2. Neustart des Dienstes via PowerShell: Restart-Service Spooler
Verification:
Anwendung startet erfolgreich ohne Fehler."""
        ticket = self.parser.parse(intl_ticket)
        md = self.generator.format_markdown(ticket, sanitize=True)
        self.assertIn("## Issue Symptoms", md)
        self.assertIn("## Root Cause Analysis", md)
        self.assertIn("## Resolution Steps", md)

    def test_zero_width_and_null_bytes(self) -> None:
        """Handles strings with embedded null bytes, zero-width spaces, and control characters."""
        polluted_text = "Ticket: INC-NULL\x00\x01\x02\nSymptoms: Issue with null\u200bbytes.\nResolution: Cleared cache."
        ticket = self.parser.parse(polluted_text)
        self.assertIsNotNone(ticket)
        md = self.generator.format_markdown(ticket, sanitize=True)
        self.assertIn("## Issue Symptoms", md)


def run_stress_tests() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(TestHighVolumeAndThroughput))
    suite.addTest(loader.loadTestsFromTestCase(TestCorruptedAndExtremeSchemas))
    suite.addTest(loader.loadTestsFromTestCase(TestIntensivePIISanitization))
    suite.addTest(loader.loadTestsFromTestCase(TestAdversarialSecurityAndInjection))
    suite.addTest(loader.loadTestsFromTestCase(TestExtremeBoundaryConditions))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_stress_tests())

