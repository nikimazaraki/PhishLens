"""Personalization detector."""

from __future__ import annotations

from ..models import Category, Signal
from ..text import normalize


def detect_personalization(
    text: str,
    recipient_name: str | None = None,
    recipient_role: str | None = None,
    recipient_employer: str | None = None,
    **_,
) -> Signal:
    norm = normalize(text)
    evidence: list[str] = []
    hits = 0

    if recipient_name and recipient_name.lower() in norm:
        hits += 1
        evidence.append(f'addresses recipient by name ("{recipient_name}")')
    if recipient_role and recipient_role.lower() in norm:
        hits += 1
        evidence.append(f'references recipient role ("{recipient_role}")')
    if recipient_employer and recipient_employer.lower() in norm:
        hits += 1
        evidence.append(f'references employer ("{recipient_employer}")')

    score = 0.0 if hits == 0 else min(0.95, 1 - 0.5**hits)

    # Only meaningful when there's a real recipient identity to check the
    # text against — a generic phrase like "your project" appears constantly
    # in ordinary business email and isn't verified OSINT residue, so it
    # shouldn't count as this detector having "checked and found nothing".
    applicable = bool(recipient_name or recipient_role or recipient_employer)

    return Signal(
        name="personalization",
        category=Category.OSINT,
        score=score,
        weight=0.15,
        technique="Targeted personalization (OSINT residue)",
        evidence=evidence,
        applicable=applicable,
    )
