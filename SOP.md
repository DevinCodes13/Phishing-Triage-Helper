# SOP: Triaging a Reported Phishing Email (Tier 1)

**Purpose:** Give Tier 1 a consistent, repeatable first pass on any email reported as suspected phishing, using the triage tool to extract indicators, run automated checks, and produce a documented risk rating before deciding on next steps.

**Scope:** Applies to any email forwarded or reported by an employee as "looks like phishing," "suspicious," or similar. This SOP does not replace judgment — it standardizes the first 5 minutes so every report gets the same baseline treatment regardless of which analyst picks it up.

---

## 1. Get the Email Into a Usable Format

- **Best case:** ask the reporting user to forward the email as an **attachment** (not inline), or export it as a `.eml` file. Most mail clients support "Forward as attachment" — this preserves the real headers, which matters for Reply-To and sender-spoofing checks.
- **If that's not possible:** copy-paste the raw email text (headers included, if visible) into a `.txt` file. The tool can still work from this, just with less header detail.
- Save the file somewhere you can point the tool at it. If multiple reports came in around the same time, drop them all in one folder — the tool can process a whole folder in one run.

## 2. Run the Tool

Single email:
```bash
python triage.py --file suspicious_email.eml
```

Multiple reports at once:
```bash
python triage.py --folder ./todays_reports/
```

Pasted text, no file needed:
```bash
python triage.py --text "$(cat pasted_email.txt)"
```

This produces a `.json` and a `.md` case summary in `./output/` by default.

## 3. Read the Risk Rating

| Rating | What it means | What you do |
|---|---|---|
| 🔴 **HIGH** | Blocklist hit, malicious attachment, or multiple strong indicators (typosquatting, VT detections, etc.) | Follow the tool's recommended actions immediately. Do not wait for Tier 2 sign-off to quarantine the email or block the domain — escalate in parallel, not instead of acting. |
| 🟡 **MEDIUM** | Some suspicious signals, but nothing conclusive (e.g. a shortened link + urgency language, no confirmed malicious verdict) | Block the flagged domain(s) proactively, warn the reporting user, and flag for a second look — either a more senior analyst or a rescan later (new domains sometimes get VirusTotal detections only after a delay). |
| 🟢 **LOW** | No meaningful findings | Archive as reviewed. If the user is a repeat reporter or seems anxious, a short reassurance reply is good practice even when there's nothing to escalate. |

**Read the Findings section, not just the color.** The rating is a starting point — a HIGH from one blocklist hit is different from a HIGH built from five smaller signals, and knowing which is which helps you explain the decision if asked.

## 4. Act on the Recommended Actions

Every case summary ends with a checklist of recommended actions specific to that email's findings (e.g. "isolate the endpoint" only appears if a suspicious attachment was actually found). Work through that list — it's meant to be copy-pasted straight into your ticket, not re-derived from scratch each time.

## 5. Document and Close

- Paste the `.md` summary into the ticket or tracking log. It's already formatted for that.
- If you overrode the tool's rating based on your own judgment (e.g. downgraded a MEDIUM after confirming with the user it was a false alarm), **note why** — this is what makes the tool's calibration improvable over time instead of just trusted blindly.
- If VirusTotal wasn't checked (no API key configured, or the domain was too new to have a verdict yet), note that too — it means the LOW/MEDIUM rating is based on local heuristics only, which is weaker evidence than a confirmed malicious verdict.

## 6. When to Escalate Beyond This SOP

Escalate to Tier 2 / Incident Response immediately, regardless of what the tool's rating says, if:

- The reporting user says they **already clicked a link or opened an attachment**
- The reporting user says they **entered credentials** on a linked site
- **Multiple users** report what looks like the same campaign
- The email appears to be a **targeted/spear-phishing** attempt referencing internal names, projects, or systems (the tool's heuristics are built for mass-phishing patterns and are less reliable against a tailored attack)

The tool is a triage aid, not a substitute for judgment on any of the above — treat a HIGH-confidence human signal (user admits they clicked) as always overriding a LOW automated score.
