# Phishing Triage Summary — 🔴 HIGH RISK

**Source:** `./examples/case_01_credential_phishing.eml`  
**Generated:** 2026-08-15T15:04:50.739441+00:00  
**Risk score:** 100  

## Email Details
- **From:** PayPal Support <security@paypa1-verify-account.com>
- **Reply-To:** recover@totally-different-domain.ru
- **Subject:** Urgent Action Required: Your account will be closed

## Indicators of Compromise
**Domains:**
- `paypa1-verify-account.com`

**URLs:**
- `http://paypa1-verify-account.com/login?id=8827`

## Findings
- **[HIGH | +30] typosquatting:** paypa1-verify-account.com contains 'paypal' (after normalizing character substitution) embedded in an unrelated domain
- **[HIGH | +25] display_name_spoofing:** Display name references 'paypal' but the sending address (paypa1-verify-account.com) has no relation to paypal.com
- **[MEDIUM | +25] urgency_language:** Contains classic urgency/pressure phrasing: "verify your account", "act now", "urgent action required" (+2 more)
- **[MEDIUM | +20] reply_to_mismatch:** Reply-To domain (totally-different-domain.ru) differs from From domain (paypa1-verify-account.com) -- replies are routed somewhere the sender's address doesn't match

## VirusTotal
_Not checked — no VT_API_KEY configured for this run. Local heuristics only._

## Recommended Actions
- [ ] Quarantine/delete the email from all mailboxes it was delivered to
- [ ] Block the sender domain and any flagged URLs/domains at the email gateway and web proxy
- [ ] Notify the reporting user and any other recipients; instruct them not to click links or open attachments
- [ ] If any recipient may have entered credentials on a linked site, force a password reset for that account
- [ ] Escalate to Tier 2 / IR if multiple users received this email or if a credential compromise is suspected
