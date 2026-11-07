# ITSM Platform Schema & Field Mapping Reference

## 1. Overview
This reference specifies the field mappings used by `ticket_to_kb.py` to extract diagnostic narratives, metadata, and resolution steps from popular IT Service Management (ITSM) platforms into standardized Knowledge-Centered Service (KCS v6) sections.

---

## 2. Supported ITSM Platforms

### 2.1 ServiceNow Incident (`incident` table)
ServiceNow incident records exported as JSON or accessed via the REST Table API (`/api/now/table/incident`) map to KCS sections as follows:

| ServiceNow Field | Field Label | Target KCS Section | Transformation Rule |
| :--- | :--- | :--- | :--- |
| `number` | Number | Article Metadata / Source Ticket | Captured as source reference `INCxxxxxxx`. |
| `short_description` | Short description | KCS Title | Sanitized and formatted with product prefix. |
| `description` | Description | Issue Symptoms | Scrubbed for PII; user symptoms extracted. |
| `close_notes` | Resolution notes | Resolution Steps & Root Cause | Primary source for technical resolution. |
| `work_notes` | Work notes | Root Cause / Troubleshooting | Parsed chronologically for diagnostic commands. |
| `comments` | Additional comments | Symptoms / Workaround | Extracted for customer interaction details. |
| `category` | Category | Article Metadata: Category | Mapped to top-level knowledge category. |
| `subcategory` | Subcategory | Article Metadata: Subcategory | Mapped to subcategory taxonomy. |
| `caller_id` | Caller | Sanitizer (Discard/Pseudonymize) | Converted to synthetic pseudonym. |
| `assigned_to` | Assigned to | Sanitizer (Discard/Pseudonymize) | Converted to technician pseudonym. |
| `cmdb_ci` | Configuration item | Environment / Affected System | Hostname or CI sanitized if internal. |

### 2.2 Jira Service Management (JSM Issues)
Jira Service Management issues exported via Jira REST API (`/rest/api/3/issue/{issueIdOrKey}`) map as follows:

| Jira JSM Field | Field Label | Target KCS Section | Transformation Rule |
| :--- | :--- | :--- | :--- |
| `key` | Issue Key | Article Metadata / Source Ticket | Captured as source reference `ITSD-xxxx`. |
| `fields.summary` | Summary | KCS Title | Sanitized and formatted with product prefix. |
| `fields.description` | Description | Issue Symptoms | User-reported symptoms and error logs extracted. |
| `fields.resolution.description` | Resolution | Resolution Steps | Primary resolution summary. |
| `fields.comment.comments[].body` | Comments | Root Cause & Resolution Steps | Parsed for commands, scripts, and root causes. |
| `fields.components[].name` | Components | Article Metadata: Category | Mapped to knowledge base component taxonomy. |
| `fields.environment` | Environment | Environment Section | OS, client version, and device models extracted. |
| `fields.reporter` | Reporter | Sanitizer (Discard/Pseudonymize) | Replaced with synthetic mock user. |
| `fields.assignee` | Assignee | Sanitizer (Discard/Pseudonymize) | Replaced with synthetic mock technician. |

### 2.3 Zendesk Support Tickets
Zendesk ticket exports (`/api/v2/tickets/{ticket_id}.json`) map as follows:

| Zendesk Field | Field Label | Target KCS Section | Transformation Rule |
| :--- | :--- | :--- | :--- |
| `id` | Ticket ID | Article Metadata / Source Ticket | Captured as source reference `#xxxxxx`. |
| `subject` | Subject | KCS Title | Sanitized and formatted for search. |
| `description` | Initial Comment | Issue Symptoms | Customer intake description. |
| `comments[].body` | Audit Comments | Root Cause & Resolution Steps | Internal technician work notes extracted. |
| `tags` | Tags | Search Aliases & Tags | Mapped directly to search index keywords. |
| `custom_fields` | Custom Ticket Fields | Environment & Diagnostics | Hostname, IP, and asset tags sanitized. |

### 2.4 Plain Text and Freeform Transcripts
When processing freeform technician notes or email work note exports:
- Key-value pairs (`Ticket: ...`, `User: ...`, `Error: ...`, `Resolution: ...`) are parsed via regular expression boundaries.
- Numbered troubleshooting steps (`1. ... 2. ...`) are extracted directly into Resolution Steps.
- Error codes matching hexadecimal patterns (`0x[0-9a-fA-F]{8}`) or event logs (`Event ID \d+`) are prioritized for Title and Symptom definitions.
- Command-line invocations (`PowerShell`, `cmd`, bash, Registry paths) are isolated into formatted code blocks.
