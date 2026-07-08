"""Command-line interface.

    python -m phishlens.cli email.txt --name Niki --brand Deloitte
    cat email.txt | python -m phishlens.cli - --json
"""

from __future__ import annotations

import argparse
import json
import sys

from .aggregate import analyze
from .models import Verdict

_COLORS = {
    Verdict.BENIGN: "\033[92m",         # green
    Verdict.SUSPICIOUS: "\033[93m",     # yellow
    Verdict.LIKELY_PHISHING: "\033[91m",  # red
    Verdict.HIGH_RISK: "\033[1;91m",    # bold red
}
_RESET = "\033[0m"


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="phishlens",
        description="Explainable detector for AI-assisted spear-phishing emails.",
    )
    p.add_argument("input", help="path to an email .txt file, or '-' for stdin")
    p.add_argument("--from", dest="from_header", help="raw From header")
    p.add_argument("--subject", help="email subject line")
    p.add_argument("--brand", dest="claimed_brand", help="brand the email claims to be")
    p.add_argument("--name", dest="recipient_name", help="recipient name")
    p.add_argument("--role", dest="recipient_role", help="recipient job role")
    p.add_argument("--employer", dest="recipient_employer", help="recipient employer")
    p.add_argument("--spf", help="SPF result (pass/fail/none/...)")
    p.add_argument("--dkim", help="DKIM result")
    p.add_argument("--dmarc", help="DMARC result")
    p.add_argument("--attach", action="append", default=None,
                   help="attachment filename (repeatable)")
    p.add_argument("--qr", action="store_true", help="email contains a QR code")
    p.add_argument("--send-hour", type=int, dest="send_hour",
                   help="hour the email was sent (0-23)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = p.parse_args(argv)

    headers = {}
    for k in ("spf", "dkim", "dmarc"):
        v = getattr(args, k)
        if v:
            headers[k] = v

    text = _read_input(args.input)
    result = analyze(
        text,
        from_header=args.from_header,
        subject=args.subject,
        claimed_brand=args.claimed_brand,
        recipient_name=args.recipient_name,
        recipient_role=args.recipient_role,
        recipient_employer=args.recipient_employer,
        headers=headers or None,
        attachments=args.attach,
        has_qr=args.qr or None,
        send_hour=args.send_hour,
    )

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    color = _COLORS.get(result.verdict, "") if sys.stdout.isatty() else ""
    reset = _RESET if color else ""
    print(f"\nRisk: {result.risk_score}/100   "
          f"Verdict: {color}{result.verdict.value.upper()}{reset}\n")
    if result.stacked_principles:
        print(f"Stacked principles: {', '.join(sorted(result.stacked_principles))}\n")
    if result.reasons:
        print("Why:")
        for r in result.reasons:
            print(f"  - {r}")
    else:
        print("No phishing indicators detected.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
