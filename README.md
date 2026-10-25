# Operation ECHOLEAK — Microsoft 365 Copilot Prompt Injection Threat Hunt

**Portfolio case study | Microsoft 365 Copilot • KQL • Microsoft 365 audit telemetry • Incident response**

> **Training Environment Disclosure:** Operation ECHOLEAK is a cybersecurity threat-hunting case study based on a simulated Microsoft 365 Copilot security incident. The investigation demonstrates the use of KQL, Microsoft 365 audit telemetry, and incident response techniques to analyze an indirect prompt injection attack. All findings and evidence originate from the training scenario and do not represent a confirmed real-world security breach.


## Executive summary

This investigation examined suspicious Microsoft 365 Copilot file access following an externally delivered Word document. The case report attributes the activity to **indirect prompt injection**: the user requested an ordinary document summary, but Copilot subsequently searched for and read unrelated sensitive files and returned external image URLs containing encoded filenames.

**Observed in the report:** 13 sensitive files accessed (five initially, eight subsequently), eight initial Graph tool calls (three `Graph.SearchFiles`, five `Graph.ReadFile`), a separate system-prompt/configuration disclosure, and an external image-URL exfiltration mechanism. **Important limitation:** the report indicates the encoded URLs exposed filenames, not the contents of the accessed files; actual delivery of HTTP requests is not independently established by the cited audit records.

## Tools and skills

- Log Analytics workspace; Kusto Query Language (KQL)
- `OfficeActivity_CL`, `CopilotAudit_CL`, `EntraSignIn_CL`
- Microsoft 365 Copilot and Graph tool-call audit analysis
- Baseline comparison, timeline reconstruction, MITRE ATLAS technique mapping, response planning

## Investigation timeline (UTC, 20 September 2026)

| Time | Reported event |
| --- | --- |
| 09:15:22 | External email delivered with a Word attachment |
| 10:42:08 | Document accessed |
| 10:42:35 | User requested a summary from Copilot |
| 10:42:41–10:42:55 | Three file searches and five file reads |
| 10:43:08 | Copilot response included external image links with encoded filenames |
| 10:44:19 | System prompt and enterprise configuration disclosed in a response |
| 10:45:30–10:45:45 | Additional keyword searches |
| 10:45:51–10:46:30 | Eight further sensitive files accessed |

## Attack chain

```text
External email → Word attachment → Copilot summary request
→ Graph.SearchFiles → Graph.ReadFile → external image URLs
→ configuration disclosure → additional sensitive-file searches/access
```

## Findings and confidence

The report classifies the incident as **external input manipulation / indirect prompt injection** (MITRE ATLAS `AML.T0051.001`). The observed Copilot behavior differs from the reported baseline of 90 events from 16 users with no ToolCall/Search events. Sign-in telemetry did not show anomalous sign-ins in the reviewed window. These observations support the case classification but are bounded by the provided lab telemetry.

**Impact caveat:** Access to 13 files does **not** prove the contents of all 13 were exfiltrated. The reported encoded URL parameters contained filenames. A network/proxy corroboration step would be needed to establish outbound retrieval and transmitted data beyond the audit response text.


## Investigation artifacts

- [Full Threat Hunt Investigation Report](01-investigation-report.md) — Detailed investigation findings, attack timeline, KQL analysis, and supporting screenshots.
- [KQL Hunting Queries](kql-queries/) — 11 queries documenting the investigation process.
- [Containment and Remediation Plan](02-containment-plan.md) — Recommended containment, investigation, and security improvements.
- [Evidence Screenshots](screenshots/) — Seven screenshots supporting key findings from the investigation.


## Recommended response

## Recommended response

The recommended next steps include blocking the suspicious sender, investigating the external domain, and quarantining copies of the malicious document. The response plan also covers reviewing affected Copilot sessions, assessing potential data exposure, and improving detection rules to identify similar activity.

See the [Containment and Remediation Plan](02-containment-plan.md) for the full recommendations.

## Scope and reproducibility

Queries refer to custom lab tables and a specific `RunId`, so they are **not** plug-and-play in a different Microsoft 365 tenant.

The repository includes seven evidence screenshots from the original investigation report, along with 11 KQL queries and supporting analysis. The underlying Word document, its embedded prompt-injection payload, and raw audit logs are not included.

This project was completed in a simulated training environment. The organization, users, email addresses, and investigation evidence are fictional and used solely for educational and portfolio purposes.


## Author

This project is part of my cybersecurity portfolio and demonstrates my hands-on experience with threat hunting, KQL, Microsoft 365 security investigations, and incident response planning.

The investigation was completed using a simulated security incident, with a focus on identifying suspicious activity, reviewing audit logs, and documenting findings.
