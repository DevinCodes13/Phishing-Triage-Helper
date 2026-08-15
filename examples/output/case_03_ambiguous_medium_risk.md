# Phishing Triage Summary — 🟡 MEDIUM RISK

**Source:** `./examples/case_03_ambiguous_medium_risk.eml`  
**Generated:** 2026-08-15T15:04:50.747437+00:00  
**Risk score:** 45  

## Email Details
- **From:** IT Helpdesk <it-helpdesk@company-secure-portal.xyz>
- **Reply-To:** (none)
- **Subject:** Password expires today - immediate action required

## Indicators of Compromise
**Domains:**
- `bit.ly`
- `company-secure-portal.xyz`

**URLs:**
- `http://bit.ly/3xK9zL2`

## Findings
- **[MEDIUM | +20] urgency_language:** Contains classic urgency/pressure phrasing: "immediate action", "password expires"
- **[MEDIUM | +15] url_shortener:** bit.ly is a URL shortener -- true destination is hidden until clicked
- **[LOW | +10] suspicious_tld:** company-secure-portal.xyz uses .xyz, a TLD frequently abused for cheap throwaway phishing domains

## VirusTotal
_Not checked — no VT_API_KEY configured for this run. Local heuristics only._

## Recommended Actions
- [ ] Block the flagged domain(s) proactively pending further review
- [ ] Warn the reporting user to avoid clicking any links or opening attachments
- [ ] Check whether other users received the same or similar message
- [ ] Re-review if VirusTotal detections increase on a later rescan (new/unknown domains often start with 0 detections)
