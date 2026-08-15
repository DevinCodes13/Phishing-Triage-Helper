"""
scoring.py

Combines local heuristic findings + VirusTotal results into a single
risk rating (low / medium / high) and a list of recommended actions.

The scoring is a simple additive point system, not a model -- every
point is traceable back to a specific Finding, and the thresholds are
plain constants at the top of this file. That's a deliberate choice:
a tier-1 analyst (or an interviewer) should be able to look at a score
of 65 and see exactly which three things added up to it, not trust a
black box.
"""

from dataclasses import dataclass
from checks import Finding
from vt_client import VTResult

LOW_MEDIUM_THRESHOLD = 20
MEDIUM_HIGH_THRESHOLD = 50

VT_MALICIOUS_POINTS_PER_VENDOR = 8      # each AV vendor flagging it adds weight
VT_SUSPICIOUS_POINTS_PER_VENDOR = 3
VT_MALICIOUS_CAP = 40                   # don't let one domain's VT score alone dominate unbounded


@dataclass
class TriageResult:
    score: int
    risk: str                      # "low" | "medium" | "high"
    findings: list[Finding]
    vt_results: list[VTResult]
    vt_checked: bool
    recommended_actions: list[str]


def score_vt_result(vt: VTResult) -> tuple[int, Finding | None]:
    if not vt.checked:
        return 0, None
    if vt.malicious == 0 and vt.suspicious == 0:
        return 0, None
    points = min(
        vt.malicious * VT_MALICIOUS_POINTS_PER_VENDOR + vt.suspicious * VT_SUSPICIOUS_POINTS_PER_VENDOR,
        VT_MALICIOUS_CAP,
    )
    severity = "high" if vt.malicious >= 3 else "medium" if (vt.malicious or vt.suspicious) else "low"
    finding = Finding(
        check="virustotal",
        detail=f"{vt.domain}: {vt.malicious} vendor(s) flagged malicious, {vt.suspicious} flagged suspicious"
               + (" (cached result)" if vt.from_cache else ""),
        points=points,
        severity=severity,
    )
    return points, finding


def compute_risk(score: int) -> str:
    if score >= MEDIUM_HIGH_THRESHOLD:
        return "high"
    if score >= LOW_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def recommend_actions(risk: str, findings: list[Finding], parsed) -> list[str]:
    actions = []
    checks_present = {f.check for f in findings}

    if risk == "high":
        actions.append("Quarantine/delete the email from all mailboxes it was delivered to")
        actions.append("Block the sender domain and any flagged URLs/domains at the email gateway and web proxy")
        actions.append("Notify the reporting user and any other recipients; instruct them not to click links or open attachments")
        if "suspicious_attachment" in checks_present:
            actions.append("If the attachment was opened, isolate the affected endpoint and run an AV/EDR scan")
        actions.append("If any recipient may have entered credentials on a linked site, force a password reset for that account")
        actions.append("Escalate to Tier 2 / IR if multiple users received this email or if a credential compromise is suspected")

    elif risk == "medium":
        actions.append("Block the flagged domain(s) proactively pending further review")
        actions.append("Warn the reporting user to avoid clicking any links or opening attachments")
        actions.append("Check whether other users received the same or similar message")
        actions.append("Re-review if VirusTotal detections increase on a later rescan (new/unknown domains often start with 0 detections)")

    else:
        actions.append("No immediate action required based on current indicators")
        actions.append("Archive the report; note as reviewed in the tracking log")
        if findings:
            actions.append("Findings were minor/low-confidence -- consider a follow-up if the user reports similar mail again")

    return actions


def triage(parsed, findings: list[Finding], vt_results: list[VTResult], vt_enabled: bool) -> TriageResult:
    all_findings = list(findings)
    score = sum(f.points for f in findings)

    for vt in vt_results:
        pts, finding = score_vt_result(vt)
        score += pts
        if finding:
            all_findings.append(finding)

    risk = compute_risk(score)
    actions = recommend_actions(risk, all_findings, parsed)

    return TriageResult(
        score=score,
        risk=risk,
        findings=all_findings,
        vt_results=vt_results,
        vt_checked=vt_enabled,
        recommended_actions=actions,
    )
