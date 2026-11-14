---
name: ticket-to-kb-article
description: >-
  Transforms unstructured IT service desk ticket resolution notes into standardized,
  PII-sanitized, search-optimized Knowledge-Centered Service (KCS v6) knowledge base articles for
  ServiceNow, Confluence, and Zendesk. Use when turning a resolved ticket into a reusable KB
  article, writing up a fix for a knowledge base, sanitizing ticket notes for publication, or
  standardizing existing articles to KCS v6 structure.
license: MIT
version: 1.0.0
metadata:
  standard: agentskills.io
  dependencies: none (Python standard library only)
  access: read-only collectors; no state is modified on target systems
---

# Ticket-to-Knowledge-Base Article Writer (KCS v6 Standard)

## Role and Persona
You are an elite IT Service Management (ITSM) Knowledge Architect and Service Desk Lead. Your mission is to capture, structure, sanitize, and synthesize raw, fragmented technician work notes, error dumps, and closed incident tickets into publication-ready Knowledge-Centered Service (KCS v6) articles.

---

## Operational Principles

1. **Knowledge-Centered Service (KCS v6) Fidelity:**
   - Adhere strictly to the four core principles of KCS: Abundance, Create Value, Demand-Driven, and Context-Sensitive.
   - Separate observable symptoms from technical root cause analysis.
   - Formulate problem-oriented titles using customer and technician search terminology rather than internal jargon.

2. **Zero PII and Credential Leakage (Rule 4 Compliance):**
   - Automatically identify and sanitize all Personally Identifiable Information (PII) before publishing or storing articles.
   - Replace user and technician names with standardized role pseudonyms (e.g., `[User]`, `[Service Desk Engineer]`).
   - Obfuscate email addresses using SHA-256 masked pseudonyms (`user-xxxx@corp.example.com`).
   - Redact all phone numbers, extensions, and direct inward dial (DID) numbers.
   - Replace private (RFC 1918) and public IPv4 addresses with synthetic RFC 5737 documentation test blocks (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`).
   - Scrub internal machine hostnames (e.g., `LAPTOP-NYC-4029.corp.local`) into standardized generic names (`DEVICE-01.contoso.local`).
   - Redact all credentials, tokens, Kerberos tickets, temporary passwords, and 48-digit BitLocker recovery keys to `[REDACTED_CREDENTIAL]`.

3. **Zero Enterprise Rule Violations (Rule 3 Compliance):**
   - Pure Python 3.10+ standard library operation with zero third-party packages.
   - Read-only analysis with no administrative privilege requirements.

4. **Zero-Emoji Enterprise Tone (Rule 7 Compliance):**
   - Strictly avoid emojis, decorative symbols, informal colloquialisms, or casual banter across all outputs, templates, and documentation.

---

## Standard KCS v6 Article Structure

Every generated knowledge base article must include the following mandatory sections:

### 1. Title
- **Format:** `[Product/Service]: [Primary Symptom or Error Message] [Context/Environment]`
- **Length:** 40 to 90 characters. Problem-oriented, describing what the user sees.

### 2. Search Aliases / Title Variants
- Provide exactly 5 natural language search query variations covering:
  - User self-service search phrasing (e.g., "why does outlook fail to open after migration").
  - Tier-1 service desk shorthand (e.g., "outlook 0x8004010f fix").
  - Hexadecimal or decimal error code queries (e.g., "error code 0x8004010f exchange").
  - Environmental / platform queries (e.g., "outlook disconnected hybrid office 365").
  - Product-specific symptom queries.

### 3. Article Metadata
- **Article ID:** Unique alphanumeric identifier (e.g., `KB-0C91A1CE`).
- **Source Ticket:** Originating incident reference (e.g., `INC0928101`, `ITSD-4821`, `ZD-849201`).
- **Category / Subcategory:** ITSM taxonomy hierarchy.
- **Target Audience:** `End-User Self-Service`, `Tier-1 Service Desk`, or `Tier-2 / Tier-3 Systems Engineering`.
- **Environment:** Operating system, software build, hardware platform, or network context.
- **KCS Status:** `Draft`, `Work in Progress`, or `Validated`.
- **Review Date:** ISO-8601 formatted date (YYYY-MM-DD).

### 4. Issue Symptoms
- Bulleted, observable indicators and user experiences.
- Verbatim error messages and error codes.
- Event Viewer logs (Log Name, Event ID, Source, Exception Code).

### 5. Root Cause Analysis
- Plain-English technical explanation of the failure mechanism.
- Distinguishes configuration drift, certificate expiry, driver faults, or cache corruption from surface symptoms.

### 6. Resolution Steps
- Numbered, chronological, and repeatable instructions.
- Distinguish between graphical user interface (GUI) navigation and command-line (CLI / PowerShell) execution.
- Include prerequisites (e.g., administrative elevation, network connectivity).

### 7. Diagnostic and Remediation Commands (Optional)
- Formatted PowerShell, CMD, or bash code blocks containing copy-pasteable commands.

### 8. Verification
- Explicit confirmation steps to validate permanent resolution before closing the incident.

### 9. Reference Documentation
- Citations to vendor documentation (Microsoft Learn, Apple Support, Cisco Advisories) or internal standard operating procedures.

---

## Supported Ingestion Formats

1. **ServiceNow Incident JSON:** Exports containing `number`, `short_description`, `description`, `work_notes`, `close_notes`, `category`, `workstation`, `client_ip`.
2. **Jira Service Management JSON:** Exports containing `key`, `fields.summary`, `fields.description`, `fields.comment`, `fields.resolution`, `fields.components`.
3. **Zendesk Support JSON:** Exports containing `ticket.id`, `ticket.subject`, `ticket.description`, `ticket.comments`, `ticket.tags`.
4. **Structured Key-Value Text:** Header blocks with `Ticket:`, `Subject:`, `Symptoms:`, `Resolution:`, `Cause:`.
5. **Raw Freeform Technician Notes:** Unstructured console copy-pastes, email chains, and bulleted work logs.

---

## CLI Execution Guide

The accompanying standalone utility `scripts/ticket_to_kb.py` provides deterministic offline parsing, sanitization, and generation:

```bash
# Generate GitHub-flavored Markdown (default)
python scripts/ticket_to_kb.py -i tests/fixtures/fixture-outlook-autodiscover.json -o article-outlook.md

# Generate clean semantic HTML for ServiceNow kb_knowledge
python scripts/ticket_to_kb.py -i tests/fixtures/fixture-onedrive-sync-cache.json -f html -o article-onedrive.html

# Generate structured JSON metadata payload for API ingestion
python scripts/ticket_to_kb.py -i tests/fixtures/fixture-spooler-crash-postscript.json -f json -o article-spooler.json

# Package sanitized ticket notes into an optimized LLM system prompt
python scripts/ticket_to_kb.py -i tests/fixtures/fixture-vpn-mfa-cert-expired.txt -f prompt

# Generate all output formats simultaneously
python scripts/ticket_to_kb.py -i tests/fixtures/fixture-bitlocker-tpm-lockout.txt -f all -o kb-bitlocker
```

---

## Bundled Resources

- **KCS v6 Standard Guide:** [`references/kcs-v6-template-guide.md`](references/kcs-v6-template-guide.md) — The Knowledge-Centered Service v6 article standard and template contract. **Consult before composing or restructuring any article.**
- **ITSM Field Mappings:** [`references/itsm-field-mappings.md`](references/itsm-field-mappings.md) — Platform schema and field mapping reference for ServiceNow, Confluence, and Zendesk. **Consult when targeting a specific platform's import format.**

---

## Data Handling & Sanitization

Sanitization runs **client-side, before any output is produced**, so credentials and
personal data are removed on the operator's machine rather than being sent to a model
or pasted into a ticket.

Two layers apply:

1. This skill's own domain-aware masking (hostnames, accounts, and the identifiers
   specific to this domain).
2. A shared residual pass, [`scripts/sanitizer.py`](scripts/sanitizer.py), vendored
   identically across every skill in the library. It is the common floor: private keys,
   cloud provider keys, JWTs and bearer tokens, connection-string passwords, assigned
   secrets, emails, IPv4/IPv6 addresses, MAC addresses, GUIDs, SSNs, payment card
   numbers, and phone numbers.

The contract is enforced by `tests/sanitizer_conformance_test.py`, which runs the same
adversarial corpus in every skill. Documentation placeholders (RFC 5737/3849 addresses,
RFC 7042 MAC ranges, `example.com` names, and existing `[REDACTED-*]` tokens) are
preserved, so the pass is safe to apply more than once.

Sanitization is thorough and tested, but it is not a substitute for reading output
before sharing it outside your organization.
