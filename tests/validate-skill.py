#!/usr/bin/env python3
"""
Test Harness for Ticket-to-Knowledge-Base Article Writer (validate-skill.py)

Validates compliance with:
- Rule 2: Hands-on local test verification.
- Rule 3: Zero external dependencies (pure Python standard library).
- Rule 4: Mandatory PII sanitization and zero-leakage guarantee.
- Rule 7: Strict zero-emoji compliance.
- Rule 9: Automated test suite returning exit code 0.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
SCRIPTS_DIR = PROJECT_DIR / "scripts"
FIXTURES_DIR = SCRIPT_DIR / "fixtures"
MIGRATOR_CLI = SCRIPTS_DIR / "ticket_to_kb.py"

# Add scripts directory to Python path for direct unit testing
sys.path.insert(0, str(SCRIPTS_DIR))
try:
    from ticket_to_kb import Sanitizer, TicketParser, KCSArticleGenerator, TicketData
except ImportError as e:
    sys.stderr.write(f"Failed to import ticket_to_kb module: {e}\n")
    sys.exit(1)


class TestKCSArticleStructure(unittest.TestCase):
    """Suite 1: KCS v6 Structure Compliance."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = TicketParser(sanitizer=self.sanitizer)
        self.generator = KCSArticleGenerator(sanitizer=self.sanitizer)

    def test_all_fixtures_generate_mandatory_headings(self) -> None:
        fixtures = list(FIXTURES_DIR.glob("fixture-*"))
        self.assertGreaterEqual(len(fixtures), 5, "Must have at least 5 test fixtures")

        mandatory_headings = [
            "## Search Aliases / Title Variants",
            "## Article Metadata",
            "## Issue Symptoms",
            "## Root Cause Analysis",
            "## Resolution Steps",
            "## Verification",
            "## Reference Documentation"
        ]

        for fix in fixtures:
            content = fix.read_text(encoding="utf-8")
            ticket = self.parser.parse(content)
            md = self.generator.format_markdown(ticket, sanitize=True)

            self.assertTrue(md.startswith("# "), f"Missing title in {fix.name}")
            for heading in mandatory_headings:
                self.assertIn(heading, md, f"Missing heading '{heading}' in {fix.name}")

    def test_metadata_fields_present(self) -> None:
        fixture_path = FIXTURES_DIR / "fixture-outlook-autodiscover.json"
        ticket = self.parser.parse(fixture_path.read_text(encoding="utf-8"))
        md = self.generator.format_markdown(ticket, sanitize=True)

        self.assertIn("**Article ID:**", md)
        self.assertIn("**Source Ticket:**", md)
        self.assertIn("**Category:**", md)
        self.assertIn("**Target Audience:**", md)
        self.assertIn("**Environment:**", md)
        self.assertIn("**KCS Status:** Validated", md)
        self.assertIn("**Last Reviewed:**", md)


class TestPIISanitizationGuarantee(unittest.TestCase):
    """Suite 2: PII Sanitization Guarantee (Rule 4 Compliance)."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = TicketParser(sanitizer=self.sanitizer)
        self.generator = KCSArticleGenerator(sanitizer=self.sanitizer)

    def test_zero_raw_pii_in_output(self) -> None:
        forbidden_strings = [
            "mock-alex.rivera@synthetic-test.local",
            "mock-sarah.chen@synthetic-test.local",
            "mock-marcus.vance@synthetic-test.local",
            "mock-elena.rostova@synthetic-test.local",
            "mock-jordan.taylor@synthetic-test.local",
            "+1-555-0199",
            "+1-555-0144",
            "+1-555-0188",
            "123456-789012-345678-901234-567890-123456-789012-345678",  # BitLocker recovery key
            "WORKSTATION-LON-01",
            "LAPTOP-SF-8812",
            "DESKTOP-ATL-9921",
            "LAPTOP-NYC-4029",
            "PRINT-CORP-01"
        ]

        fixtures = list(FIXTURES_DIR.glob("fixture-*"))
        for fix in fixtures:
            content = fix.read_text(encoding="utf-8")
            ticket = self.parser.parse(content)
            md = self.generator.format_markdown(ticket, sanitize=True)
            html_out = self.generator.format_html(ticket, sanitize=True)
            json_out = self.generator.format_json(ticket, sanitize=True)

            for forbidden in forbidden_strings:
                self.assertNotIn(forbidden, md, f"Found leaked PII '{forbidden}' in {fix.name} markdown")
                self.assertNotIn(forbidden, html_out, f"Found leaked PII '{forbidden}' in {fix.name} html")
                self.assertNotIn(forbidden, json_out, f"Found leaked PII '{forbidden}' in {fix.name} json")

    def test_masked_email_format(self) -> None:
        raw = "Contact technician user-test@contoso.local for assistance."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertRegex(scrubbed, r"user-[a-f0-9]{8}@corp\.example\.com")

    def test_bitlocker_recovery_key_redacted(self) -> None:
        key = "111111-222222-333333-444444-555555-666666-777777-888888"
        scrubbed = self.sanitizer.scrub(f"Recovery key is {key}")
        self.assertIn("[REDACTED_CREDENTIAL]", scrubbed)
        self.assertNotIn(key, scrubbed)


class TestMultiFormatParsing(unittest.TestCase):
    """Suite 3: Multi-Format Parsing & Source Types."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = TicketParser(sanitizer=self.sanitizer)

    def test_parse_servicenow_json(self) -> None:
        fix = FIXTURES_DIR / "fixture-outlook-autodiscover.json"
        ticket = self.parser.parse(fix.read_text(encoding="utf-8"))
        self.assertEqual(ticket.ticket_id, "INC0928101")
        self.assertEqual(ticket.category, "Software")
        self.assertIn("0x8004010F", ticket.error_codes)
        self.assertGreaterEqual(len(ticket.resolution_steps), 1)

    def test_parse_jira_json(self) -> None:
        fix = FIXTURES_DIR / "fixture-onedrive-sync-cache.json"
        ticket = self.parser.parse(fix.read_text(encoding="utf-8"))
        self.assertEqual(ticket.ticket_id, "ITSD-4821")
        self.assertIn("0x8004de40", ticket.error_codes)
        self.assertTrue(any("onedrive.exe /reset" in c for c in ticket.commands))

    def test_parse_zendesk_json(self) -> None:
        fix = FIXTURES_DIR / "fixture-spooler-crash-postscript.json"
        ticket = self.parser.parse(fix.read_text(encoding="utf-8"))
        self.assertEqual(ticket.ticket_id, "ZD-849201")
        self.assertIn("0xc0000005", ticket.error_codes)
        self.assertTrue(any("Stop-Service -Name Spooler" in c for c in ticket.commands))

    def test_parse_raw_text_report(self) -> None:
        fix = FIXTURES_DIR / "fixture-vpn-mfa-cert-expired.txt"
        ticket = self.parser.parse(fix.read_text(encoding="utf-8"))
        self.assertEqual(ticket.ticket_id, "INC0481920")
        self.assertIn("RPC error 0x800706BA", ticket.error_codes)
        self.assertTrue(any("certutil -pulse" in c for c in ticket.commands))

    def test_parse_freeform_ticket_notes(self) -> None:
        fix = FIXTURES_DIR / "fixture-bitlocker-tpm-lockout.txt"
        ticket = self.parser.parse(fix.read_text(encoding="utf-8"))
        self.assertEqual(ticket.ticket_id, "REQ0039182")
        self.assertIn("Event ID 834", ticket.error_codes)
        self.assertTrue(any("Suspend-BitLocker" in c for c in ticket.commands))


class TestSearchOptimization(unittest.TestCase):
    """Suite 4: Search Optimization Quality."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = TicketParser(sanitizer=self.sanitizer)
        self.generator = KCSArticleGenerator(sanitizer=self.sanitizer)

    def test_generates_exact_five_search_aliases(self) -> None:
        fixtures = list(FIXTURES_DIR.glob("fixture-*"))
        for fix in fixtures:
            ticket = self.parser.parse(fix.read_text(encoding="utf-8"))
            aliases = self.generator.generate_search_aliases(ticket)
            self.assertEqual(len(aliases), 5, f"Expected 5 aliases for {fix.name}, got {len(aliases)}")
            # Aliases should be non-empty and unique
            self.assertEqual(len(set(aliases)), 5, f"Aliases must be unique for {fix.name}")


class TestITSMExportFormats(unittest.TestCase):
    """Suite 5: Multi-Format Export Verification."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = TicketParser(sanitizer=self.sanitizer)
        self.generator = KCSArticleGenerator(sanitizer=self.sanitizer)
        fix = FIXTURES_DIR / "fixture-outlook-autodiscover.json"
        self.ticket = self.parser.parse(fix.read_text(encoding="utf-8"))

    def test_html_format_validity(self) -> None:
        html_out = self.generator.format_html(self.ticket, sanitize=True)
        self.assertTrue(html_out.startswith('<div class="kcs-article">'))
        self.assertTrue(html_out.endswith('</div>'))
        self.assertIn('<h2>Symptoms</h2>', html_out)
        self.assertIn('<h2>Resolution Steps</h2>', html_out)

    def test_json_schema_validity(self) -> None:
        json_out = self.generator.format_json(self.ticket, sanitize=True)
        data = json.loads(json_out)
        required_keys = [
            "article_id", "source_ticket", "title", "search_aliases",
            "category", "audience", "environment", "symptoms",
            "root_cause", "resolution_steps", "verification", "tags"
        ]
        for key in required_keys:
            self.assertIn(key, data)
        self.assertEqual(len(data["search_aliases"]), 5)

    def test_prompt_format_validity(self) -> None:
        prompt_out = self.generator.format_prompt(self.ticket)
        self.assertIn("You are an elite IT Service Management Knowledge Architect", prompt_out)
        self.assertIn("INSTRUCTIONS:", prompt_out)
        self.assertIn("RAW RESOLUTION & WORK NOTES:", prompt_out)

    def test_cli_all_format_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_base = Path(tmpdir) / "test_kb"
            fix = FIXTURES_DIR / "fixture-outlook-autodiscover.json"
            cmd = [
                sys.executable,
                str(MIGRATOR_CLI),
                "-i", str(fix),
                "-f", "all",
                "-o", str(out_base)
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"CLI all failed: {res.stderr}")

            self.assertTrue(Path(tmpdir, "test_kb.md").exists())
            self.assertTrue(Path(tmpdir, "test_kb.html").exists())
            self.assertTrue(Path(tmpdir, "test_kb.json").exists())


class TestResilienceAndEdgeCases(unittest.TestCase):
    """Suite 6: Resilience and Edge Cases."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = TicketParser(sanitizer=self.sanitizer)
        self.generator = KCSArticleGenerator(sanitizer=self.sanitizer)

    def test_empty_input(self) -> None:
        ticket = self.parser.parse("")
        md = self.generator.format_markdown(ticket)
        self.assertIn("## Issue Symptoms", md)

    def test_whitespace_input(self) -> None:
        ticket = self.parser.parse("   \n\t  \n  ")
        md = self.generator.format_markdown(ticket)
        self.assertIn("## Issue Symptoms", md)

    def test_malformed_json_falls_back_to_plaintext(self) -> None:
        malformed = '{"title": "Broken JSON Ticket", "unclosed": '
        ticket = self.parser.parse(malformed)
        self.assertIsNotNone(ticket)
        self.assertIn("Broken JSON Ticket", ticket.raw_notes)

    def test_large_ticket_history_performance(self) -> None:
        # 10,000 lines of simulated work notes
        large_ticket = "Ticket: INC999999\nCategory: Infrastructure\n\nWORK NOTES:\n" + "\n".join(
            f"2026-11-01 10:{i%60:02d} - Tech User: Checked log line {i} with error 0x8004010F"
            for i in range(10000)
        )
        t0 = time.perf_counter()
        ticket = self.parser.parse(large_ticket)
        md = self.generator.format_markdown(ticket, sanitize=True)
        t1 = time.perf_counter()
        elapsed = t1 - t0
        self.assertLess(elapsed, 3.0, f"Processing 10,000 lines took {elapsed:.2f}s, expected < 3.0s")
        self.assertIn("## Resolution Steps", md)


class TestZeroEmojiCompliance(unittest.TestCase):
    """Suite 7: Strict Zero-Emoji Compliance (Rule 7)."""

    EMOJI_PATTERN = re.compile(
        r"[\U00010000-\U0010ffff]|[\u2600-\u27bf]|[\u2300-\u23ff]|[\u2b50-\u2b55]"
    )

    def test_code_and_docs_are_zero_emoji(self) -> None:
        scan_extensions = [".py", ".md", ".json", ".txt", ".html"]
        for ext in scan_extensions:
            for path in PROJECT_DIR.rglob(f"*{ext}"):
                if ".git" in path.parts:
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
                emojis = self.EMOJI_PATTERN.findall(content)
                self.assertEqual(
                    len(emojis), 0,
                    f"File '{path.relative_to(PROJECT_DIR)}' contains emojis: {emojis}"
                )


def run_tests() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(TestKCSArticleStructure))
    suite.addTest(loader.loadTestsFromTestCase(TestPIISanitizationGuarantee))
    suite.addTest(loader.loadTestsFromTestCase(TestMultiFormatParsing))
    suite.addTest(loader.loadTestsFromTestCase(TestSearchOptimization))
    suite.addTest(loader.loadTestsFromTestCase(TestITSMExportFormats))
    suite.addTest(loader.loadTestsFromTestCase(TestResilienceAndEdgeCases))
    suite.addTest(loader.loadTestsFromTestCase(TestZeroEmojiCompliance))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
