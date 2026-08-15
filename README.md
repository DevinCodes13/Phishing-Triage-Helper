# Phishing Triage Helper

A command-line tool that takes a suspected phishing email — a `.eml` file, a folder of them, or just pasted text — and produces a short, consistent triage summary: extracted indicators of compromise, the checks run against them, a risk rating, and recommended next steps.

Built to standardize the first few minutes of Tier-1 phishing triage: instead of an analyst manually eyeballing headers and links, every report gets the same baseline checks and a documented, explainable score.

## What It Does

1. **Parses** the email — sender, reply-to, subject, URLs, domains, attachments — from a real `.eml` file or loosely-formatted pasted text
2. **Checks** each domain/URL against:
   - A local blocklist file
   - Typosquatting/lookalike-domain heuristics (edit distance, leetspeak substitution, brand-name-as-subdomain patterns)
   - URL shorteners, IP-literal URLs, suspicious TLDs
   - Reply-To mismatches, display-name spoofing, urgency/pressure language, malicious attachment extensions
   - **VirusTotal** domain reputation (if an API key is configured — works fully without one, just with fewer data points)
3. **Scores** everything with a transparent, additive point system — every point in the final score traces back to a specific, named finding, not a black box
4. **Outputs** a JSON case summary (for feeding into a SIEM/ticket) and a Markdown summary (for pasting straight into a ticket or Slack)

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env   # add your VirusTotal API key, or leave blank to run without it

python triage.py --file suspicious_email.eml
python triage.py --folder ./inbox_reports/
python triage.py --text "$(cat pasted_email.txt)"
```

Output lands in `./output/` by default (`--out` to change it, `--format json|markdown|both` to control what gets written).

## Example Cases

Four worked examples are in [`examples/`](./examples), with their generated output committed in [`examples/output/`](./examples/output) so you can see real input/output without running anything:

| Case | Risk | What it demonstrates |
|---|---|---|
| `case_01_credential_phishing` | 🔴 HIGH | Typosquatted domain, display-name spoofing, Reply-To mismatch, urgency language |
| `case_02_malicious_attachment` | 🔴 HIGH | Double-extension attachment (`Invoice.pdf.exe`) |
| `case_03_ambiguous_medium_risk` | 🟡 MEDIUM | URL shortener + suspicious TLD + mild urgency — flagged for review, not auto-escalated |
| `case_04_legitimate_email` | 🟢 LOW | A normal, benign email — confirms the tool doesn't cry wolf on ordinary mail |

## Design Notes

- **No API key required.** VirusTotal is optional and additive — every local check (blocklist, heuristics) runs regardless, so the tool is still useful in an air-gapped or budget-constrained environment.
- **Rate-limit and cache aware.** The free VirusTotal tier is capped at 500 requests/day and 4/minute. Results are cached to disk for a week and calls are self-throttled, so re-running the tool on the same case doesn't burn quota.
- **Explainable scoring, not a model.** Every point added to the risk score comes from a named check with a plain-English reason attached. An analyst — or an interviewer — can see exactly why a case scored the way it did.
- **Fails soft, not hard.** Messy input, a missing API key, a network hiccup, or an unrecognized email format all degrade to "do less, but still produce a usable summary" rather than crashing.

## SOP

[`SOP.md`](./SOP.md) — how a Tier-1 analyst uses this tool end-to-end when an employee reports a phish, including when to escalate past the tool's rating entirely (e.g. a user who already entered credentials).

## Project Structure

```
triage.py          CLI entry point
ioc_extract.py      Email parsing + IOC extraction
checks.py           Local heuristic + blocklist checks
vt_client.py         VirusTotal API client (caching, rate limiting)
scoring.py           Risk scoring + recommended actions
report.py            JSON/Markdown output formatting
data/
  blocklist.txt       Sample local domain blocklist
  brand_domains.txt    Known-brand domains for typosquat detection
examples/            Four worked example cases + generated output
SOP.md               Tier-1 usage procedure
```

## Tools Used

Python 3.11+, `requests` (VirusTotal API), `python-dotenv` (local config) — no other dependencies.
