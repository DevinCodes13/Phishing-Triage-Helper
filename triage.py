#!/usr/bin/env python3
"""
triage.py -- Phishing Triage Helper

Takes a suspected phishing email (a .eml file, a folder of .eml files,
or plain pasted text) and produces a short, consistent triage summary:
IOCs extracted, checks run, a risk rating, and recommended next steps.

Usage:
    python triage.py --file suspicious_email.eml
    python triage.py --file report.txt
    python triage.py --folder ./inbox_reports/
    python triage.py --text "From: ...\\nSubject: ...\\n\\nBody..."

    --format json|markdown|both   (default: both)
    --out DIR                     (default: ./output)
    --no-vt                       (skip VirusTotal even if a key is configured)

VirusTotal is used automatically if VT_API_KEY is set in the environment
(or in a local .env file). Without it, the tool still runs fully using
the local blocklist + heuristic checks -- it just notes that VT wasn't
checked, rather than failing.
"""

import os
import sys
import argparse
import glob

from ioc_extract import parse_email_file, parse_email_text
from checks import run_local_checks
from vt_client import VirusTotalClient
from scoring import triage as run_scoring
from report import to_json, to_markdown

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv is optional -- env vars set another way still work


def process_one(parsed, vt_client: VirusTotalClient, use_vt: bool):
    findings = run_local_checks(parsed)
    vt_results = []
    if use_vt and vt_client.enabled and parsed.domains:
        vt_results = vt_client.check_domains(parsed.domains)
    result = run_scoring(parsed, findings, vt_results, vt_enabled=(use_vt and vt_client.enabled))
    return result


def safe_stem(source: str) -> str:
    base = os.path.basename(source)
    base = os.path.splitext(base)[0]
    base = "".join(c if c.isalnum() or c in "-_" else "_" for c in base)
    return base or "case"


def write_outputs(parsed, result, out_dir: str, fmt: str):
    os.makedirs(out_dir, exist_ok=True)
    stem = safe_stem(parsed.source)
    written = []
    if fmt in ("json", "both"):
        path = os.path.join(out_dir, f"{stem}.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(to_json(parsed, result))
        written.append(path)
    if fmt in ("markdown", "both"):
        path = os.path.join(out_dir, f"{stem}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(to_markdown(parsed, result))
        written.append(path)
    return written


def print_summary(parsed, result):
    risk_label = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH"}[result.risk]
    print(f"\n{'=' * 60}")
    print(f"  {parsed.source}")
    print(f"  Risk: {risk_label}  (score: {result.score})")
    print(f"  Findings: {len(result.findings)}")
    if parsed.domains:
        print(f"  Domains: {', '.join(parsed.domains)}")
    print(f"{'=' * 60}\n")


def main():
    ap = argparse.ArgumentParser(description="Phishing Triage Helper")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="Path to a single .eml or .txt file")
    src.add_argument("--folder", help="Path to a folder of .eml/.txt files")
    src.add_argument("--text", help="Raw email text passed directly on the command line")

    ap.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    ap.add_argument("--out", default="./output", help="Output directory (default: ./output)")
    ap.add_argument("--no-vt", action="store_true", help="Skip VirusTotal even if a key is configured")
    ap.add_argument("--quiet", action="store_true", help="Suppress the console summary, just write files")

    args = ap.parse_args()
    vt_client = VirusTotalClient()
    use_vt = not args.no_vt

    if not use_vt:
        pass
    elif not vt_client.enabled:
        print("[i] No VT_API_KEY found -- running with local checks only. "
              "Set VT_API_KEY in your environment or a .env file to enable VirusTotal.\n", file=sys.stderr)

    targets = []
    if args.file:
        targets = [args.file]
    elif args.folder:
        targets = sorted(glob.glob(os.path.join(args.folder, "*.eml"))) + \
                  sorted(glob.glob(os.path.join(args.folder, "*.txt")))
        if not targets:
            print(f"No .eml or .txt files found in {args.folder}", file=sys.stderr)
            sys.exit(1)

    if args.text:
        parsed = parse_email_text(args.text)
        result = process_one(parsed, vt_client, use_vt)
        if not args.quiet:
            print_summary(parsed, result)
        paths = write_outputs(parsed, result, args.out, args.format)
        for p in paths:
            print(f"Wrote {p}")
        return

    for target in targets:
        parsed = parse_email_file(target)
        result = process_one(parsed, vt_client, use_vt)
        if not args.quiet:
            print_summary(parsed, result)
        paths = write_outputs(parsed, result, args.out, args.format)
        for p in paths:
            print(f"Wrote {p}")


if __name__ == "__main__":
    main()
