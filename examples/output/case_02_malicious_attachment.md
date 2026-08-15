# Phishing Triage Summary — 🔴 HIGH RISK

**Source:** `./examples/case_02_malicious_attachment.eml`  
**Generated:** 2026-08-15T15:04:50.744441+00:00  
**Risk score:** 50  

## Email Details
- **From:** Billing Department <billing@vendor-invoices-payments.net>
- **Reply-To:** (none)
- **Subject:** Invoice attached

## Indicators of Compromise
**Domains:**
- `vendor-invoices-payments.net`

**Attachments:**
- `Invoice_84421.pdf.exe` ⚠️ suspicious extension

## Findings
- **[HIGH | +50] suspicious_attachment:** Attachment 'Invoice_84421.pdf.exe' has an extension commonly used to deliver malware

## VirusTotal
_Not checked — no VT_API_KEY configured for this run. Local heuristics only._

## Recommended Actions
- [ ] Quarantine/delete the email from all mailboxes it was delivered to
- [ ] Block the sender domain and any flagged URLs/domains at the email gateway and web proxy
- [ ] Notify the reporting user and any other recipients; instruct them not to click links or open attachments
- [ ] If the attachment was opened, isolate the affected endpoint and run an AV/EDR scan
- [ ] If any recipient may have entered credentials on a linked site, force a password reset for that account
- [ ] Escalate to Tier 2 / IR if multiple users received this email or if a credential compromise is suspected
