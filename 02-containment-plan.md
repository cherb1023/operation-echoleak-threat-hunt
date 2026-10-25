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

- Review Copilot's access permissions to determine whether users have access to more sensitive information than they need.
- Look into ways to restrict external images and links in Copilot responses.
- Create alerts for unusual spikes in sensitive-file access, especially when multiple unrelated documents are accessed after a summarization request.
- Monitor Copilot responses for suspicious external URLs containing long or encoded query parameters.
- Check whether other users received the same attachment and review their Copilot activity for similar behavior.
- Share the findings with the Blue Team and detection engineering teams to help improve monitoring and identify gaps in the available logs.

## Validation

Before implementing these recommendations, confirm which controls are supported in the organization's Microsoft 365 environment. Any new detection rules should also be tested to make sure they identify suspicious activity without generating unnecessary alerts.
