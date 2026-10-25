# Response and containment plan

These are **recommendations**, not actions reported as completed.

## Immediate containment

- Block the sender `quarterly.reports@globalfinancereview.net` and review the sending domain `globalfinancereview.net` for related activity.
- Identify and quarantine copies of `Q3-2026-Global-Markets-Review.docx` across affected mailboxes.
- Investigate any outbound connections to `metrics-cdn.analyticshub.io` and block the domain if confirmed malicious.

## Impact assessment

- Review the 13 accessed files with their respective data owners to determine what sensitive information may have been exposed.
- Check DNS, proxy, and network logs to see whether the external image URLs were actually requested and whether any data was transmitted.
- Work with the legal and compliance teams to determine whether the findings require additional reporting or notification.

## Hardening and detection

- Review Copilot access scopes and least-privilege permissions.
- Evaluate restrictions on externally hosted images/links in generated responses.
- Alert on bursts of unrelated first-time sensitive-file reads following summarization requests.
- Inspect Copilot responses for external URLs with long encoded query parameters.
- Hunt for other recipients of the attachment and sessions exhibiting similar patterns.
- Brief Blue Team and detection engineering teams on the mechanism and telemetry gaps.

## Validation

Confirm each control is technically supported in the actual tenant and test detections for false positives before deployment.
