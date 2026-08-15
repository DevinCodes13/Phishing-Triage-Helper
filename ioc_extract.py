"""
ioc_extract.py

Parses a suspected phishing email (raw .eml, or loosely-formatted plain
text with header:value lines) and pulls out the indicators of compromise
we care about for triage: sender, reply-to, URLs, domains, and attachments.

Works on two kinds of input:
  1. Real .eml files (RFC 822 format, what Outlook/Gmail export)
  2. Plain pasted text, as long as it has "From:", "Subject:" etc. as the
     first few lines followed by a blank line and the body -- this covers
     the common case of an employee just copy-pasting a suspicious email
     into a text file.

If neither header style is detected, we fall back to treating the whole
input as body text and just extract URLs from it -- so the tool never
hard-fails on messy input, it just returns fewer IOCs.
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser
from dataclasses import dataclass, field
from urllib.parse import urlparse


URL_RE = re.compile(
    r"""(?xi)
    \b
    (?:https?://|www\.)
    [^\s<>"'\)\]]+
    """
)

# Loosened: catches "hxxp://" and "hxxps://" defanged URLs too, which
# analysts and threat intel feeds commonly use so the link isn't clickable.
DEFANGED_URL_RE = re.compile(
    r"""(?xi)
    \b
    hxxps?://
    [^\s<>"'\)\]]+
    """
)

EMAIL_ADDR_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

SUSPICIOUS_ATTACHMENT_EXT = {
    ".exe", ".scr", ".js", ".vbs", ".vbe", ".bat", ".cmd", ".ps1",
    ".jar", ".hta", ".wsf", ".lnk", ".msi", ".com", ".pif",
}


@dataclass
class ParsedEmail:
    source: str                     # filename or "<pasted text>"
    from_addr: str | None = None
    from_display: str | None = None
    reply_to: str | None = None
    subject: str | None = None
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    suspicious_attachments: list[str] = field(default_factory=list)
    body_text: str = ""
    raw_headers: dict = field(default_factory=dict)


def _domain_from_url(url: str) -> str | None:
    # de-fang normalization so hxxp -> http before parsing
    normalized = re.sub(r"^hxxp", "http", url, flags=re.IGNORECASE)
    normalized = normalized.replace("[.]", ".").replace("(.)", ".")
    try:
        parsed = urlparse(normalized if "://" in normalized else "http://" + normalized)
        host = parsed.netloc.split("@")[-1]  # strip userinfo if present
        host = host.split(":")[0]            # strip port if present
        return host.lower() or None
    except Exception:
        return None


def _extract_urls(text: str) -> list[str]:
    found = set()
    for m in URL_RE.finditer(text):
        found.add(m.group(0).rstrip(".,;:!?"))
    for m in DEFANGED_URL_RE.finditer(text):
        found.add(m.group(0).rstrip(".,;:!?"))
    return sorted(found)


def _looks_like_eml(raw: bytes) -> bool:
    head = raw[:2000].decode("utf-8", errors="ignore").lower()
    return bool(re.search(r"^(from|received|content-type|mime-version):", head, re.MULTILINE))


def parse_email_bytes(raw: bytes, source: str = "<input>") -> ParsedEmail:
    """Parse raw bytes that could be a real .eml or loosely-formatted pasted text."""
    if _looks_like_eml(raw):
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        return _parse_message(msg, source)

    # Fallback: try parsing as plain text with header:value lines anyway --
    # email.parser is forgiving and will grab whatever headers it can find.
    text = raw.decode("utf-8", errors="ignore")
    try:
        msg = Parser(policy=policy.default).parsestr(text)
        parsed = _parse_message(msg, source)
        if parsed.from_addr or parsed.subject:
            return parsed
    except Exception:
        pass

    # Last resort: no recognizable headers at all -- treat entire input as body.
    parsed = ParsedEmail(source=source, body_text=text)
    parsed.urls = _extract_urls(text)
    parsed.domains = sorted({d for u in parsed.urls if (d := _domain_from_url(u))})
    return parsed


def _parse_message(msg: "email.message.EmailMessage", source: str) -> ParsedEmail:
    parsed = ParsedEmail(source=source)

    from_header = msg.get("From", "")
    parsed.raw_headers["From"] = from_header
    if from_header:
        display, addr = email.utils.parseaddr(from_header)
        parsed.from_addr = addr or None
        parsed.from_display = display or None

    reply_to_header = msg.get("Reply-To", "")
    parsed.raw_headers["Reply-To"] = reply_to_header
    if reply_to_header:
        _, rt_addr = email.utils.parseaddr(reply_to_header)
        parsed.reply_to = rt_addr or None

    parsed.subject = msg.get("Subject", None)

    # Body: prefer text/plain, fall back to text/html stripped of tags,
    # fall back to whatever the message body is if it's not multipart.
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp.lower():
                continue
            if ctype == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    pass
        if not body:
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    try:
                        html = part.get_content()
                        body += re.sub(r"<[^>]+>", " ", html)
                    except Exception:
                        pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = str(msg.get_payload())

    parsed.body_text = body or ""

    # Attachments
    if msg.is_multipart():
        for part in msg.walk():
            disp = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()
            if filename and ("attachment" in disp.lower() or part.get_content_maintype() not in ("text", "multipart")):
                parsed.attachments.append(filename)
                for ext in SUSPICIOUS_ATTACHMENT_EXT:
                    if filename.lower().endswith(ext):
                        parsed.suspicious_attachments.append(filename)
                # double-extension trick, e.g. invoice.pdf.exe
                stem_parts = filename.lower().split(".")
                if len(stem_parts) > 2 and f".{stem_parts[-1]}" in SUSPICIOUS_ATTACHMENT_EXT:
                    if filename not in parsed.suspicious_attachments:
                        parsed.suspicious_attachments.append(filename)

    # URLs: pull from body plus any HTML link hrefs plus the subject itself
    search_space = parsed.body_text + " " + (parsed.subject or "")
    parsed.urls = _extract_urls(search_space)
    domain_set = {d for u in parsed.urls if (d := _domain_from_url(u))}

    # Sender's own domain is an IOC too -- worth a reputation/typosquat
    # check even if the email contains no links at all.
    if parsed.from_addr and "@" in parsed.from_addr:
        domain_set.add(parsed.from_addr.split("@")[-1].lower())

    parsed.domains = sorted(domain_set)
    return parsed


def parse_email_file(path: str) -> ParsedEmail:
    with open(path, "rb") as f:
        raw = f.read()
    return parse_email_bytes(raw, source=path)


def parse_email_text(text: str, source: str = "<pasted text>") -> ParsedEmail:
    return parse_email_bytes(text.encode("utf-8"), source=source)
