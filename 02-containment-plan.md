# Response and containment plan

These are **recommendations**, not actions reported as completed.

## Immediate containment

- Block the sender `quarterly.reports@globalfinancereview.net` and investigate the sending domain `globalfinancereview.net`.
- Quarantine the attachment `Q3-2026-Global-Markets-Review.docx` across mailboxes after validating matches.
- Block or investigate outbound requests to `metrics-cdn.analyticshub.io` through relevant DNS/proxy controls.

## Impact assessment

- Review the 13 accessed files with data owners and determine whether any contents were disclosed.
- Check network/proxy evidence for image URL retrieval and determine what data actually left the environment.
- Engage legal and compliance stakeholders for any reporting or notification decisions.

## Hardening and detection

- Review Copilot access scopes and least-privilege permissions.
- Evaluate restrictions on externally hosted images/links in generated responses.
- Alert on bursts of unrelated first-time sensitive-file reads following summarization requests.
- Inspect Copilot responses for external URLs with long encoded query parameters.
- Hunt for other recipients of the attachment and sessions exhibiting similar patterns.
- Brief Blue Team and detection engineering teams on the mechanism and telemetry gaps.

## Validation

Confirm each control is technically supported in the actual tenant and test detections for false positives before deployment.
