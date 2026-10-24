# Investigation report — Operation ECHOLEAK

## Scenario and objective

The source report describes a financial advisory firm's Microsoft 365 Copilot environment and a suspicious file-access alert. A financial analyst received an external Word document, opened it, and asked Copilot to summarize it. The investigation sought to distinguish ordinary summarization from attacker-directed behavior.

## Evidence sources

- `OfficeActivity_CL`: email receipt and file access
- `CopilotAudit_CL`: user prompts, tool calls, responses and external image URLs
- `EntraSignIn_CL`: sign-in review

See the [11 original KQL queries](kql-queries/) for the actual investigative filters and projected fields. Portal screenshots in the source report were displayed in EDT; times in this portfolio are UTC.

## Reconstruction

1. **Delivery and trigger.** At 09:15:22 UTC on September 20, 2026, an external email delivered `Q3-2026-Global-Markets-Review.docx`. The document was accessed at 10:42:08 UTC; the user then requested a summary at 10:42:35 UTC, roughly 87 minutes after delivery.
2. **Tool-use anomaly.** Copilot performed three `Graph.SearchFiles` and five `Graph.ReadFile` calls in approximately 14 seconds, accessing five unrelated sensitive files. The report's prior-access query returned no earlier access to those named files in the scoped lab data.
3. **Response-based leakage.** At 10:43:08 UTC, Copilot produced markdown image URLs to `metrics-cdn.analyticshub.io` with Base64-encoded filenames in a `d=` parameter. The report says these were filenames rather than file contents. The audit response alone does not establish whether a client fetched every URL.
4. **Configuration disclosure.** At 10:44:19 UTC, a response contained system-prompt and enterprise-configuration information.
5. **Further enumeration.** Additional searches used `confidential`, `restricted`, `board`, `acquisition`, and `salary`, followed by access to eight more sensitive files. The report counted **13 unique sensitive files** overall.
6. **Alternative explanations.** The reviewed sign-in telemetry showed no anomalous sign-ins; the configuration file was observed as read rather than modified. The report concluded indirect prompt injection rather than account or configuration compromise.

## Baseline and detection rationale

A comparison of 90 earlier Copilot events across 16 users found no tool-call/search events in the scoped data. The combination of first-time access to unrelated files, rapid tool calls, and external encoded image links provides stronger evidence than any one signal alone.

## Classification

- **Primary mechanism:** external input manipulation / indirect prompt injection
- **MITRE ATLAS mapping in source report:** `AML.T0051.001`
- **Potential effects:** unauthorized file access, filename disclosure via image URLs, system-prompt/configuration disclosure
- **Evidence limitation:** file contents were not visible in the audit logs; no proof that all accessed file contents were exfiltrated

## Lessons learned

Treat retrieved documents as untrusted input; audit Copilot tool use as well as ordinary file access; correlate unusually fast, unrelated file reads with external response URLs; and verify the impact of access separately from the impact of exfiltration.

## Original source

Adapted from the author's 12-page *Threat Hunt Report: Operation ECHOLEAK Investigation* (October 2026). This write-up summarizes the source and does not claim independent validation of its underlying telemetry.
