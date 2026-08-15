"""
checks.py

All the checks that don't require an external API: local blocklist
lookups, and pattern-based heuristics (typosquatting, display-name
spoofing, urgency language, shortened links, IP-literal URLs, etc.)

Every check returns a Finding with a point value and a plain-English
reason. The scoring module just sums these up -- the logic here is
intentionally simple and inspectable rather than a black-box model,
since the whole point of a tier-1 triage tool is that an analyst can
see exactly *why* something got flagged.
"""

import os
import re
from dataclasses import dataclass


@dataclass
class Finding:
    check: str
    detail: str
    points: int          # contribution to the risk score
    severity: str         # "info" | "low" | "medium" | "high"


DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "tiny.cc",
}

URGENCY_PHRASES = [
    "verify your account", "account suspended", "act now", "immediate action",
    "urgent action required", "your account will be closed", "click here immediately",
    "confirm your identity", "unusual activity detected", "password expires",
    "limited time", "failure to respond", "final notice", "restricted access",
    "unauthorized login attempt", "validate your account", "suspended due to",
]

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".xyz", ".top", ".review", ".click", ".gq", ".tk",
    ".ml", ".cf", ".ga", ".work", ".support", ".loan",
}


def _load_lines(filename: str) -> list[str]:
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]


def _levenshtein(a: str, b: str) -> int:
    """Standard edit distance, no external dependency needed for this."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def check_blocklist(domains: list[str]) -> list[Finding]:
    """Exact + suffix match against a local known-bad domain list."""
    blocklist = set(_load_lines("blocklist.txt"))
    findings = []
    for d in domains:
        hit = d in blocklist or any(d.endswith("." + b) for b in blocklist)
        if hit:
            findings.append(Finding(
                check="blocklist",
                detail=f"{d} matches an entry in the local blocklist",
                points=50,
                severity="high",
            ))
    return findings


LEETSPEAK_MAP = str.maketrans({"1": "l", "0": "o", "3": "e", "5": "s", "4": "a", "7": "t"})


def _normalize_leetspeak(s: str) -> str:
    return s.translate(LEETSPEAK_MAP)


def check_typosquatting(domains: list[str]) -> list[Finding]:
    """
    Flags domains that are suspiciously close to, or clearly built around,
    a well-known brand name -- but aren't the real brand domain. Covers
    three patterns seen constantly in real phishing:
      1. Close edit distance to the whole brand domain (paypa1.com)
      2. Brand name used as the first subdomain/component of an unrelated
         domain (paypal.com.security-verify.ru, or paypal-secure-login.ru)
      3. Leetspeak substitution embedded in a longer domain
         (paypa1-verify-account.com -> normalizes to contain "paypal")
    """
    brands = _load_lines("brand_domains.txt")
    findings = []
    for d in domains:
        bare = d[4:] if d.startswith("www.") else d
        normalized = _normalize_leetspeak(bare)
        flagged = False

        for brand in brands:
            if bare == brand:
                break  # exact match to a known-good brand domain, not suspicious

            brand_name = brand.split(".")[0]

            # Pattern 1: whole-domain edit distance close to the brand's full domain
            dist = _levenshtein(bare, brand)
            if 0 < dist <= 2 and len(bare) >= len(brand) - 2:
                findings.append(Finding(
                    check="typosquatting",
                    detail=f"{d} is suspiciously similar to known brand domain {brand} (edit distance {dist})",
                    points=30, severity="high",
                ))
                flagged = True
                break

            # Pattern 2: brand name is the domain's leading label, but the
            # domain doesn't actually end with the real brand domain
            first_label = bare.split(".")[0].split("-")[0]
            if first_label == brand_name and not bare.endswith(brand):
                findings.append(Finding(
                    check="typosquatting",
                    detail=f"{d} uses '{brand_name}' as part of an unrelated domain -- classic lookalike pattern",
                    points=30, severity="high",
                ))
                flagged = True
                break

            # Pattern 3: brand name appears (after undoing leetspeak
            # substitution) embedded anywhere in a longer domain
            if brand_name in normalized and not bare.endswith(brand):
                findings.append(Finding(
                    check="typosquatting",
                    detail=f"{d} contains '{brand_name}' (after normalizing character substitution) embedded in an unrelated domain",
                    points=30, severity="high",
                ))
                flagged = True
                break

        if flagged:
            continue
    return findings


def check_shorteners(domains: list[str]) -> list[Finding]:
    findings = []
    for d in domains:
        if d in URL_SHORTENERS:
            findings.append(Finding(
                check="url_shortener",
                detail=f"{d} is a URL shortener -- true destination is hidden until clicked",
                points=15,
                severity="medium",
            ))
    return findings


def check_ip_literal_urls(urls: list[str]) -> list[Finding]:
    ip_re = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
    findings = []
    for u in urls:
        if ip_re.match(u.replace("hxxp", "http")):
            findings.append(Finding(
                check="ip_literal_url",
                detail=f"{u} uses a raw IP address instead of a domain name -- unusual for legitimate mail",
                points=25,
                severity="high",
            ))
    return findings


def check_suspicious_tld(domains: list[str]) -> list[Finding]:
    findings = []
    for d in domains:
        for tld in SUSPICIOUS_TLDS:
            if d.endswith(tld):
                findings.append(Finding(
                    check="suspicious_tld",
                    detail=f"{d} uses {tld}, a TLD frequently abused for cheap throwaway phishing domains",
                    points=10,
                    severity="low",
                ))
                break
    return findings


def check_reply_to_mismatch(from_addr: str | None, reply_to: str | None) -> list[Finding]:
    if not from_addr or not reply_to:
        return []
    from_domain = from_addr.split("@")[-1].lower()
    reply_domain = reply_to.split("@")[-1].lower()
    if from_domain != reply_domain:
        return [Finding(
            check="reply_to_mismatch",
            detail=f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}) -- replies are routed somewhere the sender's address doesn't match",
            points=20,
            severity="medium",
        )]
    return []


def check_display_name_spoofing(from_display: str | None, from_addr: str | None) -> list[Finding]:
    """
    Flags a From header like 'PayPal Support <random123@gmail.com>' -- a
    trusted-looking display name paired with an unrelated free-mail or
    unrelated domain in the actual address.
    """
    if not from_display or not from_addr:
        return []
    brands = _load_lines("brand_domains.txt")
    display_lower = from_display.lower()
    addr_domain = from_addr.split("@")[-1].lower()
    findings = []
    for brand in brands:
        brand_name = brand.split(".")[0]
        if brand_name in display_lower and not addr_domain.endswith(brand):
            findings.append(Finding(
                check="display_name_spoofing",
                detail=f"Display name references '{brand_name}' but the sending address ({addr_domain}) has no relation to {brand}",
                points=25,
                severity="high",
            ))
            break
    return findings


def check_urgency_language(subject: str | None, body: str) -> list[Finding]:
    text = f"{subject or ''} {body}".lower()
    hits = [p for p in URGENCY_PHRASES if p in text]
    if hits:
        shown = ", ".join(f'"{h}"' for h in hits[:3])
        more = f" (+{len(hits) - 3} more)" if len(hits) > 3 else ""
        return [Finding(
            check="urgency_language",
            detail=f"Contains classic urgency/pressure phrasing: {shown}{more}",
            points=min(10 * len(hits), 25),
            severity="low" if len(hits) < 2 else "medium",
        )]
    return []


def check_suspicious_attachments(suspicious_attachments: list[str]) -> list[Finding]:
    findings = []
    for name in suspicious_attachments:
        findings.append(Finding(
            check="suspicious_attachment",
            detail=f"Attachment '{name}' has an extension commonly used to deliver malware",
            points=50,
            severity="high",
        ))
    return findings


def run_local_checks(parsed) -> list[Finding]:
    """Run every local (non-API) check against a ParsedEmail and return all findings."""
    findings: list[Finding] = []
    findings += check_blocklist(parsed.domains)
    findings += check_typosquatting(parsed.domains)
    findings += check_shorteners(parsed.domains)
    findings += check_ip_literal_urls(parsed.urls)
    findings += check_suspicious_tld(parsed.domains)
    findings += check_reply_to_mismatch(parsed.from_addr, parsed.reply_to)
    findings += check_display_name_spoofing(parsed.from_display, parsed.from_addr)
    findings += check_urgency_language(parsed.subject, parsed.body_text)
    findings += check_suspicious_attachments(parsed.suspicious_attachments)
    return findings
