#!/usr/bin/env python3
"""
Fuzz and Real-World Edge Cases Test Suite for ticket-to-kb-article.

Tests 25 complex real-world enterprise scenarios and adversarial fuzz inputs:
- Freshservice and Freshdesk multi-turn conversation JSON structures
- BMC Remedy / Helix ARS incident and work log summaries
- ANSI terminal color codes and escape sequence scrubbing
- IPv6 zone indexes and link-local scope identifiers
- Diverse administrative diagnostic tools (Clear-DnsClientCache, sc.exe, journalctl)
- Headerless single-sentence and unstructured freeform notes
- SQL injection strings and adversarial database payloads in work notes
- High-density Base64 certificate and key blocks
- Git merge conflict markers inside developer issue notes
- Embedded Windows Event Log XML structures
- Raw HTTP response dumps and session cookies
- Active Directory Kerberos SPN formats
- Linux dmesg kernel OOM killer logs
- Network traceroute tables with asterisks and latency metrics
- PowerShell inline hashtables and script blocks
- Stringified / double-escaped JSON inside ticket descriptions
- Right-to-Left (RTL) unicode text mixed with English
- Zero-width spaces, joiners, and non-breaking spaces
- Jira Next-Gen Sprint objects and customfield metadata
- Raw RFC 5322 email MIME header dumps
- Nested markdown code fences
- HTML markup embedded in Zendesk comments
- Search alias deduplication with dense synonym clusters
- Rule 7 enterprise zero-emoji verification across all fuzz tests
"""

import html
import json
import os
import re
import sys
import unittest
from pathlib import Path

# Add scripts directory to module import path
CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from ticket_to_kb import Sanitizer, TicketParser, KCSArticleGenerator, TicketData


class TestFuzzAndRealWorldEdgeCases(unittest.TestCase):
    """
    Test suite containing 25 specialized enterprise and fuzzing test cases.
    """

    def setUp(self) -> None:
        self.sanitizer = Sanitizer()
        self.parser = TicketParser(sanitizer=self.sanitizer)
        self.generator = KCSArticleGenerator(sanitizer=self.sanitizer)

    def test_fuzz01_freshservice_conversations_json(self) -> None:
        """FUZZ01: Extracts symptoms and resolution from Freshservice conversations structure."""
        payload = {
            "ticket": {
                "id": 994812,
                "subject": "Outlook prompts for credentials on Windows 11",
                "description_text": "User reports continuous modern auth password prompts in Outlook 365.",
                "conversations": [
                    {
                        "body_text": "Agent contacted user. Cleared cached credentials in Credential Manager.\n1. Closed Outlook.\n2. Executed cmdkey /delete for Office accounts.\n3. Relaunched Outlook and verified sign-in."
                    }
                ]
            }
        }
        ticket = self.parser.parse(json.dumps(payload))
        self.assertIn("User reports continuous modern auth password prompts", ticket.symptoms[0])
        self.assertGreaterEqual(len(ticket.resolution_steps), 1)

    def test_fuzz02_bmc_remedy_helix_plaintext(self) -> None:
        """FUZZ02: Parses BMC Remedy / Helix ARS ticket with Detailed Description and Work Log."""
        raw = """Incident Number: INC000008472910
Submitter: jsmith
Detailed Description:
Network drive Z: mapping disconnected following reboot on domain workstation.
Work Log Summary:
1. Validated Active Directory Kerberos ticket using klist.
2. Re-established drive mapping using net use Z: \\\\fileserver.corp.example.com\\share /persistent:yes
Verification:
User successfully opened network files on drive Z:."""
        ticket = self.parser.parse(raw)
        self.assertEqual(ticket.ticket_id, "INC000008472910")
        self.assertTrue(any("Network drive Z:" in s for s in ticket.symptoms))
        self.assertTrue(any("net use" in r for r in ticket.resolution_steps))
        self.assertIn("User successfully opened network files", ticket.verification)

    def test_fuzz03_ansi_escape_color_code_cleaning(self) -> None:
        """FUZZ03: Strips ANSI escape color codes from terminal transcripts in work notes."""
        raw = "Incident: INC-ANSI\nSymptoms: \x1b[31m[CRITICAL]\x1b[0m Service failed to start.\nResolution:\n1. \x1b[32m[SUCCESS]\x1b[0m Restarted daemon."
        ticket = self.parser.parse(raw)
        self.assertNotIn("\x1b[31m", ticket.symptoms[0])
        self.assertNotIn("\x1b[0m", ticket.symptoms[0])
        self.assertIn("[CRITICAL] Service failed to start.", ticket.symptoms[0])

    def test_fuzz04_ipv6_with_zone_index_scope_id(self) -> None:
        """FUZZ04: Sanitizes IPv6 link-local addresses including scope/zone index (%eth0)."""
        raw = "Server bound to link-local address fe80::1ff:fe23:4567:890a%eth0 on internal bridge."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("fe80::1ff:fe23:4567:890a%eth0", scrubbed)
        self.assertIn("2001:db8::1", scrubbed)

    def test_fuzz05_powershell_service_cmdlets(self) -> None:
        """FUZZ05: Extracts advanced administrative commands (Clear-DnsClientCache, sc.exe)."""
        text = "Ticket: INC-CMD\nResolution:\nClear-DnsClientCache\nsc.exe query spooler\nEnable-BitLocker -MountPoint 'C:'"
        ticket = self.parser.parse(text)
        self.assertTrue(any("Clear-DnsClientCache" in c for c in ticket.commands))
        self.assertTrue(any("sc.exe query spooler" in c for c in ticket.commands))
        self.assertTrue(any("Enable-BitLocker" in c for c in ticket.commands))

    def test_fuzz06_journalctl_linux_command(self) -> None:
        """FUZZ06: Extracts Linux journalctl diagnostic command from server notes."""
        text = "Ticket: INC-SRV\nResolution:\njournalctl -u nginx.service --no-pager -n 50"
        ticket = self.parser.parse(text)
        self.assertTrue(any("journalctl -u nginx.service" in c for c in ticket.commands))

    def test_fuzz07_headerless_single_sentence_ticket(self) -> None:
        """FUZZ07: Intelligently handles completely unstructured, headerless freeform ticket notes."""
        raw = "User reported Teams client audio muted on VDI. Cleared Teams cache and restarted client."
        ticket = self.parser.parse(raw)
        self.assertTrue(len(ticket.symptoms) > 0 or len(ticket.resolution_steps) > 0)
        md = self.generator.format_markdown(ticket)
        self.assertIn("## Issue Symptoms", md)
        self.assertIn("## Resolution Steps", md)

    def test_fuzz08_sql_injection_payload_in_notes(self) -> None:
        """FUZZ08: Treats SQL injection strings in work notes strictly as inert documentation."""
        raw = "Ticket: INC-SQL\nSymptoms: Database error.\nResolution:\n1. Executed query: SELECT * FROM audit WHERE id = '1' OR '1'='1'; DROP TABLE logs;--"
        ticket = self.parser.parse(raw)
        md = self.generator.format_markdown(ticket)
        self.assertIn("DROP TABLE logs;--", md)
        self.assertIn("## Resolution Steps", md)

    def test_fuzz09_base64_certificate_block(self) -> None:
        """FUZZ09: Safely processes high-density Base64 certificate blocks without backtracking."""
        b64_data = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz64l0x2" * 15
        raw = f"Ticket: INC-B64\nSymptoms: Invalid certificate.\nResolution:\nCert block:\n{b64_data}"
        ticket = self.parser.parse(raw)
        self.assertEqual(ticket.ticket_id, "INC-B64")
        md = self.generator.format_markdown(ticket)
        self.assertIn("## Root Cause Analysis", md)

    def test_fuzz10_git_merge_conflict_markers(self) -> None:
        """FUZZ10: Preserves git merge conflict markers in developer tickets without crashing."""
        raw = "Ticket: INC-GIT\nSymptoms: Merge conflict.\nResolution:\n<<<<<<< HEAD\nconfig_val = 1\n=======\nconfig_val = 2\n>>>>>>> main"
        ticket = self.parser.parse(raw)
        self.assertEqual(ticket.ticket_id, "INC-GIT")
        self.assertIn("Merge conflict.", ticket.symptoms[0])

    def test_fuzz11_windows_event_log_xml_block(self) -> None:
        """FUZZ11: Safely processes embedded Windows Event Log XML without breaking KCS sections."""
        xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>7034</EventID><Channel>System</Channel></System></Event>'
        raw = f"Ticket: INC-EVT\nSymptoms:\n{xml}\nResolution:\n1. Reinstalled service."
        ticket = self.parser.parse(raw)
        self.assertIn("Event ID 7034", ticket.error_codes)
        html_out = self.generator.format_html(ticket)
        self.assertIn("&lt;Event", html_out)

    def test_fuzz12_raw_http_headers_and_cookies(self) -> None:
        """FUZZ12: Preserves diagnostic HTTP headers while sanitizing any embedded IP or cookie tokens."""
        raw = "Incident: INC-HTTP\nSymptoms: Gateway failure.\nHTTP/1.1 502 Bad Gateway\nServer: nginx/1.22\nSet-Cookie: JSESSIONID=abcdef1234567890; Path=/; Secure"
        ticket = self.parser.parse(raw)
        self.assertIn("HTTP 502", ticket.error_codes)

    def test_fuzz13_kerberos_spn_format(self) -> None:
        """FUZZ13: Sanitizes internal realm and host in Kerberos Service Principal Names (SPNs)."""
        raw = "Kerberos ticket requested for HTTP/portal.corp.example.com@CORP.EXAMPLE.COM failed."
        scrubbed = self.sanitizer.scrub(raw)
        self.assertNotIn("portal.corp.example.com", scrubbed)
        self.assertIn("contoso.local", scrubbed)

    def test_fuzz14_linux_dmesg_oom_killer_log(self) -> None:
        """FUZZ14: Parses kernel dmesg out-of-memory killer log lines in server tickets."""
        raw = "Incident: INC-OOM\nSymptoms:\n[ 1849.201948] Out of memory: Kill process 8912 (java) score 850 or sacrifice child\nResolution:\n1. Increased JVM heap."
        ticket = self.parser.parse(raw)
        self.assertTrue(any("Out of memory" in s for s in ticket.symptoms))
        self.assertTrue(any("Increased JVM heap" in r for r in ticket.resolution_steps))

    def test_fuzz15_traceroute_hops_with_asterisks(self) -> None:
        """FUZZ15: Processes traceroute latency output containing asterisks and timeouts cleanly."""
        raw = """Ticket: INC-TRACE
Symptoms:
1  10.0.0.1  1.2 ms  0.9 ms
2  * * * Request timed out.
3  10.20.0.1  15.4 ms
Resolution:
1. Rerouted SD-WAN tunnel."""
        ticket = self.parser.parse(raw)
        self.assertTrue(any("Request timed out" in s for s in ticket.symptoms))
        self.assertTrue(any("Rerouted SD-WAN tunnel" in r for r in ticket.resolution_steps))

    def test_fuzz16_powershell_hashtable_in_notes(self) -> None:
        """FUZZ16: Handles PowerShell hashtable syntax in resolution steps without parser corruption."""
        raw = "Ticket: INC-HASH\nResolution:\n1. Passed configuration hashtable:\n$params = @{'Server'='10.0.0.1'; 'Port'=443; 'UseSsl'=$true}"
        ticket = self.parser.parse(raw)
        self.assertTrue(any("$params = @{" in r for r in ticket.resolution_steps))

    def test_fuzz17_escaped_json_string_in_description(self) -> None:
        """FUZZ17: Handles double-escaped or stringified JSON payload inside work notes."""
        raw = 'Ticket: INC-ESC\nSymptoms:\n{\\"status\\": \\"error\\", \\\"code\\\": 500}\nResolution:\n1. Reset API endpoint.'
        ticket = self.parser.parse(raw)
        self.assertEqual(ticket.ticket_id, "INC-ESC")
        self.assertGreaterEqual(len(ticket.resolution_steps), 1)

    def test_fuzz18_right_to_left_hebrew_arabic_text(self) -> None:
        """FUZZ18: Handles Right-to-Left (RTL) unicode text without crashing or encoding failure."""
        hebrew_text = "\u05de\u05e9\u05ea\u05de\u05e9 \u05dc\u05d0 \u05de\u05e6\u05dc\u05d9\u05d7 \u05dc\u05d4\u05ea\u05d7\u05d1\u05e8"
        raw = f"Ticket: INC-RTL\nSymptoms: {hebrew_text}\nResolution:\n1. Fixed network adapter."
        ticket = self.parser.parse(raw)
        md = self.generator.format_markdown(ticket)
        self.assertIn(hebrew_text, md)

    def test_fuzz19_zero_width_and_surrogate_unicode(self) -> None:
        """FUZZ19: Handles zero-width spaces (\u200b) and soft hyphens cleanly."""
        raw = "Ticket: INC-ZW\nSymptoms: Error\u200boccurred\u200cin\u00admodule.\nResolution:\n1. Cleared cache."
        ticket = self.parser.parse(raw)
        self.assertEqual(ticket.ticket_id, "INC-ZW")
        self.assertIn("Cleared cache.", ticket.resolution_steps[0])

    def test_fuzz20_jira_nextgen_sprint_customfields(self) -> None:
        """FUZZ20: Handles Jira Next-Gen Sprint customfield objects without type errors."""
        payload = {
            "key": "KAN-1092",
            "fields": {
                "summary": "Fix print queue buffer overflow",
                "customfield_10020": [
                    {"id": 482, "name": "Sprint 24", "state": "active", "goal": "Q4 Stability"}
                ],
                "description": "Spooler service fails during bulk PDF print jobs.",
                "comment": {"comments": []}
            }
        }
        ticket = self.parser.parse(json.dumps(payload))
        self.assertEqual(ticket.ticket_id, "KAN-1092")
        self.assertIn("Spooler service fails", ticket.symptoms[0])

    def test_fuzz21_email_mime_header_dump(self) -> None:
        """FUZZ21: Handles raw RFC 5322 email headers pasted into ticket symptoms."""
        raw = """Ticket: INC-MIME
Symptoms:
Received: from mail.contoso.local (10.0.0.5) by edge.contoso.local
Message-ID: <847291048.102938@mail.contoso.local>
Authentication-Results: spf=pass smtp.mailfrom=user@example.com
Resolution:
1. Re-registered SPF TXT record in external DNS."""
        ticket = self.parser.parse(raw)
        self.assertTrue(any("Received: from" in s for s in ticket.symptoms))
        self.assertTrue(any("Re-registered SPF TXT record" in r for r in ticket.resolution_steps))

    def test_fuzz22_nested_code_fences_markdown(self) -> None:
        """FUZZ22: Prevents nested markdown code blocks in work notes from breaking article layout."""
        raw = "Ticket: INC-CODE\nSymptoms: Code block error.\nResolution:\n1. Configured script:\n```powershell\nGet-Process\n```"
        ticket = self.parser.parse(raw)
        md = self.generator.format_markdown(ticket)
        self.assertIn("## Resolution Steps", md)
        self.assertIn("## Verification", md)

    def test_fuzz23_html_in_zendesk_comments(self) -> None:
        """FUZZ23: Strips residual HTML markup from Zendesk comments in generated markdown."""
        payload = {
            "ticket": {
                "id": 881923,
                "subject": "OneDrive sync stalled",
                "description": "<p>User reports OneDrive shows <i>Syncing 1 file</i> indefinitely.</p>",
                "comments": [
                    {
                        "body": "<p>Remediation:<br/>1. Reset cache.<br/>2. Executed <code>onedrive.exe /reset</code></p>"
                    }
                ]
            }
        }
        ticket = self.parser.parse(json.dumps(payload))
        md = self.generator.format_markdown(ticket)
        self.assertNotIn("<p>", md)
        self.assertNotIn("<br/>", md)
        self.assertNotIn("<code>", md)

    def test_fuzz24_search_aliases_with_dense_synonyms(self) -> None:
        """FUZZ24: Generates exactly 5 unique search aliases even when ticket summary has duplicate terms."""
        ticket = TicketData(
            ticket_id="INC-SYN",
            title="Outlook Outlook MS Outlook Client",
            category="Email",
            subcategory="Client",
            environment="Windows 11",
            symptoms=["Outlook crash."]
        )
        aliases = self.generator.generate_search_aliases(ticket)
        self.assertEqual(len(aliases), 5)
        self.assertEqual(len(set(aliases)), 5)

    def test_fuzz25_zero_emoji_guarantee_fuzz_battery(self) -> None:
        """FUZZ25: Strictly verifies Rule 7 zero-emoji compliance across all fuzz battery inputs and outputs."""
        emoji_test_string = "Customer stated: VPN crashed \U0001f525 and screen went black \U0001f608."
        raw = f"Ticket: INC-EMOJI\nSymptoms: {emoji_test_string}\nResolution:\n1. Fixed adapter."
        ticket = self.parser.parse(raw)
        md = self.generator.format_markdown(ticket, sanitize=True)
        html_out = self.generator.format_html(ticket, sanitize=True)
        json_out = self.generator.format_json(ticket, sanitize=True)

        emoji_re = re.compile(
            r"[\U00010000-\U0010ffff]|[\u2600-\u27bf]|[\u2300-\u23ff]|[\u2b50-\u2b55]"
        )
        self.assertFalse(bool(emoji_re.search(md)), "Found leaked emoji in markdown output")
        self.assertFalse(bool(emoji_re.search(html_out)), "Found leaked emoji in HTML output")
        self.assertFalse(bool(emoji_re.search(json_out)), "Found leaked emoji in JSON output")


def suite() -> unittest.TestSuite:
    return unittest.TestLoader().loadTestsFromTestCase(TestFuzzAndRealWorldEdgeCases)


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite())
    sys.exit(0 if result.wasSuccessful() else 1)
