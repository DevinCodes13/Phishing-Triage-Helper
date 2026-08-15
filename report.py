"""
report.py

Turns a ParsedEmail + TriageResult into the two output formats:
  - JSON: for feeding into a SIEM, ticket, or another tool
  - Markdown: for pasting straight into a ticket, Slack message, or
    email reply to the reporting user
"""

import json
from datetime import datetime, timezone


def to_dict(parsed, result) -> dict:
    return {
        "source": parsed.source,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "email": {
            "from_address": parsed.from_addr,
            "from_display_name": parsed.from_display,
            "reply_to": parsed.reply_to,
            "subject": parsed.subject,
        },
        "iocs": {
            "urls": parsed.urls,
            "domains": parsed.domains,
            "attachments": parsed.attachments,
            "suspicious_attachments": parsed.suspicious_attachments,
        },
        "virustotal_checked": result.vt_checked,
        "virustotal_results": [
            {
                "domain": v.domain,
                "checked": v.checked,
                "malicious_vendor_count": v.malicious,
                "suspicious_vendor_count": v.suspicious,
                "harmless_vendor_count": v.harmless,
                "error": v.error,
                "from_cache": v.from_cache,
            }
            for v in result.vt_results
        ],
        "findings": [
            {"check": f.check, "detail": f.detail, "points": f.points, "severity": f.severity}
            for f in result.findings
        ],
        "risk_score": result.score,
        "risk_rating": result.risk,
        "recommended_actions": result.recommended_actions,
    }


def to_json(parsed, result, indent: int = 2) -> str:
    return json.dumps(to_dict(parsed, result), indent=indent)


def to_markdown(parsed, result) -> str:
    d = to_dict(parsed, result)
    risk_emoji = {"low": "\U0001F7E2", "medium": "\U0001F7E1", "high": "\U0001F534"}.get(result.risk, "")

    lines = []
    lines.append(f"# Phishing Triage Summary \u2014 {risk_emoji} {result.risk.upper()} RISK")
    lines.append("")
    lines.append(f"**Source:** `{parsed.source}`  ")
    lines.append(f"**Generated:** {d['generated_at']}  ")
    lines.append(f"**Risk score:** {result.score}  ")
    lines.append("")

    lines.append("## Email Details")
    lines.append(f"- **From:** {parsed.from_display or ''} <{parsed.from_addr or 'unknown'}>")
    lines.append(f"- **Reply-To:** {parsed.reply_to or '(none)'}")
    lines.append(f"- **Subject:** {parsed.subject or '(none)'}")
    lines.append("")

    lines.append("## Indicators of Compromise")
    if parsed.domains:
        lines.append("**Domains:**")
        for dom in parsed.domains:
            lines.append(f"- `{dom}`")
    else:
        lines.append("_No domains extracted._")
    lines.append("")
    if parsed.urls:
        lines.append("**URLs:**")
        for u in parsed.urls:
            lines.append(f"- `{u}`")
        lines.append("")
    if parsed.attachments:
        lines.append("**Attachments:**")
        for a in parsed.attachments:
            flag = " \u26A0\uFE0F suspicious extension" if a in parsed.suspicious_attachments else ""
            lines.append(f"- `{a}`{flag}")
        lines.append("")

    lines.append("## Findings")
    if result.findings:
        for f in sorted(result.findings, key=lambda x: -x.points):
            sev_tag = f.severity.upper()
            lines.append(f"- **[{sev_tag} | +{f.points}] {f.check}:** {f.detail}")
    else:
        lines.append("_No findings from local checks or VirusTotal._")
    lines.append("")

    lines.append("## VirusTotal")
    if not result.vt_checked:
        lines.append("_Not checked \u2014 no VT_API_KEY configured for this run. Local heuristics only._")
    elif not result.vt_results:
        lines.append("_No domains to check._")
    else:
        for v in result.vt_results:
            if not v.checked:
                lines.append(f"- `{v.domain}`: could not check ({v.error})")
            else:
                cache_note = " (cached)" if v.from_cache else ""
                lines.append(f"- `{v.domain}`: {v.malicious} malicious / {v.suspicious} suspicious / {v.harmless} harmless{cache_note}")
    lines.append("")

    lines.append("## Recommended Actions")
    for a in result.recommended_actions:
        lines.append(f"- [ ] {a}")
    lines.append("")

    return "\n".join(lines)
