"""Personalization detector.

Attackers build a profile of a target from their public digital footprint
(LinkedIn, company sites, social media). That research is invisible in the
delivered email, but its residue is not: the message knows the recipient's
name, role, employer, or a recent project. Fusing specific personal knowledge
with a request is the tell of a researched, targeted attack - what separates
spear phishing from mass spam.

Personalization alone is not malicious (real colleagues know your name too), so
this detector is weighted modestly and gains force in the ensemble when it
co-occurs with a credential/action request or urgency.
"""

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

    # Generic OSINT-flavored cues that imply the sender researched the target,
    # even when we were not given explicit context fields.
    osint_cues = [
        "your recent", "your paper", "your project", "your team",
        "as the new", "in your department", "on your linkedin",
        "your presentation", "your role as", "since you joined",
    ]
    cue_matches = [c for c in osint_cues if c in norm]
    if cue_matches:
        hits += 1
        evidence.append(f'context-specific references: "{cue_matches[0]}"')

    # 0 hits -> 0.0; 1 -> 0.5; 2 -> 0.75; 3+ -> ~0.9. Personalization saturates
    # because the *presence* of targeting matters more than its exact count.
    score = 0.0 if hits == 0 else min(0.95, 1 - 0.5 ** hits)

    return Signal(
        name="personalization",
        category=Category.OSINT,
        score=score,
        weight=0.15,
        technique="Targeted personalization (OSINT residue)",
        evidence=evidence,
    )
