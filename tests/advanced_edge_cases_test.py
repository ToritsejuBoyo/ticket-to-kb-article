#!/usr/bin/env python3
"""
Advanced Enterprise Edge Case Test Battery (advanced_edge_cases_test.py)

Contains 25 advanced edge cases covering:
1. Jira Cloud Atlassian Document Format (ADF) AST extraction.
2. ServiceNow [code] tag and residual HTML markup cleaning.
3. Hardware MAC address sanitization (IEEE 802 & Cisco dot notations).
4. Cloud API tokens (AWS AKIA, GitHub ghp_, Slack xoxb-).
5. Payment and government identifiers (16-digit cards, SSNs).
6. Multi-line and cross-platform command detection (systemctl, reg, gpupdate).
7. Non-technical tickets and audience tier classification.
8. Mixed CRLF/CR/LF line ending normalization.
9. Search alias deduplication and semantic taxonomy mapping.
10. Zero-Emoji compliance across all advanced outputs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
SCRIPTS_DIR = PROJECT_DIR / "scripts"

sys.path.insert(0, str(SCRIPTS_DIR))
from ticket_to_kb import Sanitizer, TicketParser, KCSArticleGenerator, TicketData


class TestAdvancedEdgeCases(unittest.TestCase):
    """25 Advanced Enterprise Edge Cases."""

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = TicketParser(sanitizer=self.sanitizer)
        self.generator = KCSArticleGenerator(sanitizer=self.sanitizer)

    def test_adv01_jira_cloud_adf_description(self) -> None:
        """ADV01: Extracts plain text from Jira Cloud Atlassian Document Format (ADF) description."""
        adf_jira = {
            "key": "ITSD-ADF-01",
            "fields": {
                "summary": "Microsoft Teams fails to initialize on virtual desktop",
                "description": {
                    "version": 1,
                    "type": "doc",
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": "User reported Teams client displays white screen on VDI."}
                            ]
                        }
                    ]
                },
                "comment": {"comments": []}
            }
        }
        ticket = self.parser.parse(json.dumps(adf_jira))
        self.assertIn("User reported Teams client displays white screen on VDI.", ticket.symptoms)

    def test_adv02_jira_cloud_adf_comments_and_code(self) -> None:
        """ADV02: Extracts resolution actions and code blocks from ADF comment trees."""
        adf_comments = {
            "key": "ITSD-ADF-02",
            "fields": {
                "summary": "Teams cache reset procedure",
                "description": "User reported crash.",
                "comment": {
                    "comments": [
                        {
                            "author": {"displayName": "Tech Kevin"},
                            "body": {
                                "version": 1,
                                "type": "doc",
                                "content": [
                                    {
                                        "type": "paragraph",
                                        "content": [
                                            {"type": "text", "text": "Action: Executed command to flush WAM cache."}
                                        ]
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        }
        ticket = self.parser.parse(json.dumps(adf_comments))
        self.assertTrue(any("Action: Executed command to flush WAM cache." in step for step in ticket.resolution_steps))

    def test_adv03_servicenow_code_tag_stripping(self) -> None:
        """ADV03: Strips ServiceNow [code] and HTML tags from description and work notes."""
        sn_ticket = {
            "number": "INC-SN-CODE",
            "short_description": "Printer spooler crash",
            "description": "[code]<p>Printer spooler service <strong>stopped</strong></p>[/code]",
            "work_notes": "[code]<pre>Restart-Service Spooler -Force</pre>[/code]\nFlushed spool directory.",
            "close_notes": "[code]<b>Service validated</b>[/code]"
        }
        ticket = self.parser.parse(json.dumps(sn_ticket))
        md = self.generator.format_markdown(ticket, sanitize=True)
        self.assertNotIn("[code]", md)
        self.assertNotIn("[/code]", md)
        self.assertNotIn("<pre>", md)
        self.assertNotIn("<strong>", md)
        self.assertIn("Printer spooler service stopped", md)

    def test_adv04_mac_address_colon_notation(self) -> None:
        """ADV04: Sanitizes IEEE 802 colon-delimited MAC addresses."""
        raw = "Device physical MAC address: 00:1A:2B:3C:4D:5E connected to port 12."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("00:1A:2B:3C:4D:5E", scrubbed)
        self.assertIn("00:00:5E:00:53:01", scrubbed)

    def test_adv05_mac_address_hyphen_notation(self) -> None:
        """ADV05: Sanitizes hyphen-delimited MAC addresses."""
        raw = "Adapter physical address: 00-1A-2B-3C-4D-5E."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("00-1A-2B-3C-4D-5E", scrubbed)
        self.assertIn("00:00:5E:00:53:01", scrubbed)

    def test_adv06_mac_address_cisco_dot_notation(self) -> None:
        """ADV06: Sanitizes Cisco dot-delimited MAC addresses."""
        raw = "Switch MAC entry: 001a.2b3c.4d5e VLAN 100."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("001a.2b3c.4d5e", scrubbed)
        self.assertIn("00:00:5E:00:53:01", scrubbed)

    def test_adv07_aws_access_key_sanitization(self) -> None:
        """ADV07: Redacts AWS Access Key ID (AKIA...) from developer tickets."""
        raw = "Configured AWS CLI with access key AKIAIOSFODNN7EXAMPLE for S3 sync."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", scrubbed)
        self.assertIn("[REDACTED_CREDENTIAL]", scrubbed)

    def test_adv08_github_token_sanitization(self) -> None:
        """ADV08: Redacts GitHub Personal Access Tokens (ghp_...)."""
        raw = "Git push failed with token ghp_11223344556677889900aabbccddeeff1122."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("ghp_11223344556677889900aabbccddeeff1122", scrubbed)
        self.assertIn("[REDACTED_CREDENTIAL]", scrubbed)

    def test_adv09_slack_token_sanitization(self) -> None:
        """ADV09: Redacts Slack Bot and User tokens (xoxb-...)."""
        raw = "Slack webhook integration bot token: xoxb-123456789012-1234567890123-abcdef123456."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("xoxb-123456789012-1234567890123-abcdef123456", scrubbed)
        self.assertIn("[REDACTED_CREDENTIAL]", scrubbed)

    def test_adv10_credit_card_number_sanitization(self) -> None:
        """ADV10: Redacts 16-digit credit card numbers mistakenly pasted in billing tickets."""
        raw = "Customer corporate purchasing card 4532-1111-2222-3333 charged for license."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("4532-1111-2222-3333", scrubbed)
        self.assertIn("[REDACTED_CREDENTIAL]", scrubbed)

    def test_adv11_social_security_number_sanitization(self) -> None:
        """ADV11: Redacts Social Security Numbers (SSNs)."""
        raw = "Employee verified ID using SSN 123-45-6789 with HR."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("123-45-6789", scrubbed)
        self.assertIn("[REDACTED_CREDENTIAL]", scrubbed)

    def test_adv12_ipv4_with_port_sanitization(self) -> None:
        """ADV12: Preserves socket port number while masking internal private IPv4 address."""
        raw = "Web service listening on 192.168.1.50:8080 and 10.0.0.1:443."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("192.168.1.50", scrubbed)
        self.assertNotIn("10.0.0.1", scrubbed)
        self.assertRegex(scrubbed, r"192\.0\.2\.\d+:8080")
        self.assertRegex(scrubbed, r"192\.0\.2\.\d+:443")

    def test_adv13_ipv4_cidr_notation_sanitization(self) -> None:
        """ADV13: Preserves CIDR prefix mask while sanitizing network address."""
        raw = "Routed internal subnet 10.240.0.0/16 across corporate IPsec tunnel."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("10.240.0.0", scrubbed)
        self.assertRegex(scrubbed, r"192\.0\.2\.\d+/16")

    def test_adv14_command_ipconfig_flushdns(self) -> None:
        """ADV14: Extracts Windows ipconfig /flushdns diagnostic command."""
        text = "Ticket: INC-DNS\nResolution:\n1. Flushed local cache:\nipconfig /flushdns"
        ticket = self.parser.parse(text)
        self.assertTrue(any("ipconfig /flushdns" in cmd for cmd in ticket.commands))

    def test_adv15_command_gpupdate_force(self) -> None:
        """ADV15: Extracts Windows gpupdate /force Group Policy command."""
        text = "Ticket: INC-GPO\nResolution:\n1. Refreshed computer policy:\ngpupdate /force"
        ticket = self.parser.parse(text)
        self.assertTrue(any("gpupdate /force" in cmd for cmd in ticket.commands))

    def test_adv16_command_registry_add(self) -> None:
        """ADV16: Extracts Windows reg add command from work notes."""
        text = 'Ticket: INC-REG\nResolution:\n1. Set registry DWORD:\nreg add "HKLM\\Software\\Policies" /v Test /t REG_DWORD /d 1 /f'
        ticket = self.parser.parse(text)
        self.assertTrue(any("reg add" in cmd for cmd in ticket.commands))

    def test_adv17_command_linux_systemctl(self) -> None:
        """ADV17: Extracts Linux systemctl command from server tickets."""
        text = "Ticket: INC-LINUX\nResolution:\n1. Restarted service:\nsystemctl restart nginx"
        ticket = self.parser.parse(text)
        self.assertTrue(any("systemctl restart nginx" in cmd for cmd in ticket.commands))

    def test_adv18_command_net_stop_start(self) -> None:
        """ADV18: Extracts legacy Windows net stop / start commands."""
        text = "Ticket: INC-NET\nResolution:\n1. Terminated spooler:\nnet stop spooler\nnet start spooler"
        ticket = self.parser.parse(text)
        self.assertTrue(any("net stop spooler" in cmd for cmd in ticket.commands))

    def test_adv19_non_technical_ticket_audience(self) -> None:
        """ADV19: Categorizes non-technical how-to tickets as End-User Self-Service."""
        ticket = TicketData(
            title="How to configure Outlook email signature",
            category="Software",
            subcategory="Email",
            commands=[],
            error_codes=[],
            raw_notes="User requested guide to add company email signature logo."
        )
        audience = self.generator._determine_audience(ticket)
        self.assertEqual(audience, "End-User Self-Service")

    def test_adv20_advanced_driver_crash_audience(self) -> None:
        """ADV20: Categorizes memory dump / driver crash tickets as Tier-2 / Tier-3 Systems Engineering."""
        ticket = TicketData(
            title="Print Spooler terminates with access violation",
            category="Infrastructure",
            commands=["Stop-Service -Name Spooler"],
            error_codes=["0xc0000005"],
            raw_notes="Faulting module hpz3r500.dll driver crash dump inspected in WinDbg."
        )
        audience = self.generator._determine_audience(ticket)
        self.assertEqual(audience, "Tier-2 / Tier-3 Systems Engineering")

    def test_adv21_mixed_crlf_and_cr_line_endings(self) -> None:
        """ADV21: Normalizes mixed Windows CRLF, Unix LF, and legacy Mac CR in a single ticket."""
        mixed_payload = "Ticket: INC-MIXED\r\nSubject: Mixed line endings\rSymptoms: Line 1\nLine 2\r\nResolution: Step 1\rStep 2\n"
        ticket = self.parser.parse(mixed_payload)
        self.assertEqual(ticket.ticket_id, "INC-MIXED")
        self.assertIn("Line 1", ticket.symptoms)
        self.assertGreaterEqual(len(ticket.resolution_steps), 1)

    def test_adv22_search_alias_deduplication(self) -> None:
        """ADV22: Generates 5 distinct, non-redundant search aliases even when error code is in title."""
        ticket = TicketData(
            title="Outlook Cannot Connect with Error 0x8004010F",
            category="Software",
            environment="Windows 11",
            error_codes=["0x8004010F"]
        )
        aliases = self.generator.generate_search_aliases(ticket)
        self.assertEqual(len(aliases), 5)
        self.assertEqual(len(set(aliases)), 5, "Search aliases must be unique")

    def test_adv23_windows_path_with_spaces_in_steps(self) -> None:
        """ADV23: Handles file paths with spaces (e.g., C:\\Program Files\\...) cleanly in resolution."""
        text = 'Ticket: INC-PATH\nResolution:\n1. Navigated to "C:\\Program Files\\Microsoft Office\\root\\Office16".\n2. Executed scanpst.exe.'
        ticket = self.parser.parse(text)
        md = self.generator.format_markdown(ticket, sanitize=True)
        self.assertIn("C:\\Program Files\\Microsoft Office\\root\\Office16", md)

    def test_adv24_powershell_multiline_backtick_continuation(self) -> None:
        """ADV24: Preserves PowerShell multi-line commands using backtick line continuations."""
        text = "Ticket: INC-BT\nResolution:\n1. Ran cleanup:\nGet-ChildItem -Path 'C:\\Temp' -Recurse `\n    -Filter '*.log' | `\n    Remove-Item -Force"
        ticket = self.parser.parse(text)
        self.assertTrue(any("Get-ChildItem" in cmd for cmd in ticket.commands))

    def test_adv25_zero_emoji_guarantee_on_advanced_battery(self) -> None:
        """ADV25: Verifies that this test file and its outputs remain 100% compliant with Rule 7."""
        file_content = Path(__file__).read_text(encoding="utf-8")
        emoji_pattern = re.compile(
            r"[\U00010000-\U0010ffff]|[\u2600-\u27bf]|[\u2300-\u23ff]|[\u2b50-\u2b55]"
        )
        self.assertEqual(len(emoji_pattern.findall(file_content)), 0)


def run_advanced_tests() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(TestAdvancedEdgeCases))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_advanced_tests())
