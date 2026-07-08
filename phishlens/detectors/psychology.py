"""Psychological manipulation tactics.

Detects the six classic persuasion levers phishing uses to short-circuit
critical thinking: reciprocation, commitment/consistency, social proof, liking,
authority, and scarcity/urgency. Combining several of these in one email is far
more effective than using one, so this detector reports *which* tactics fired
(not just an aggregate) and the scoring engine escalates when several co-occur.

Each tactic has a small bank of surface cues. The banks are intentionally
conservative and easy to audit; they are the natural swap point for an
embedding/LLM classifier later.
"""

from __future__ import annotations

from ..models import Category, Signal
from ..text import normalize

# Phrase banks. Substrings, matched case-insensitively against normalized text.
PRINCIPLES: dict[str, list[str]] = {
    # 1. Reciprocation: unsolicited "favor" that creates obligation, then asks.
    "reciprocation": [
        "we have upgraded", "we've upgraded", "we have improved", "as a courtesy",
        "free of charge", "complimentary", "we've credited", "we have added",
        "on your behalf", "we've secured your", "we have secured your",
        "as a thank you", "we've enabled", "we have enabled",
    ],
    # 2. Commitment & Consistency: reference a prior agreement to compel follow-through.
    "commitment": [
        "you agreed", "as you requested", "as requested", "per your request",
        "you signed up", "you registered", "you enrolled", "as agreed",
        "updated terms", "terms and conditions", "policy violation",
        "you recently", "to remain compliant", "as per our agreement",
    ],
    # 3. Social Proof: "everyone is doing it" to normalize the request.
    "social_proof": [
        "all customers", "all employees", "all users", "all staff",
        "company-wide", "everyone", "most users", "others have already",
        "your colleagues", "join thousands", "mandatory for all",
        "new company policy", "all account holders",
    ],
    # 4. Liking: warmth / similarity / flattery to lower guard. Weak on its own.
    "liking": [
        "great work", "as a valued", "we appreciate you", "hope you're well",
        "hope you are well", "it was great to", "loved your", "impressed by your",
        "as one of our best", "your recent success",
    ],
    # 5. Authority: impersonate a role/institution to compel unquestioning compliance.
    "authority": [
        "it department", "it support", "help desk", "helpdesk", "system administrator",
        "administrator", "security team", "compliance team", "compliance department",
        "hr department", "human resources", "legal department", "chief executive",
        "ceo", "cfo", "on behalf of management", "official notice",
        "verify your identity", "your bank", "account security team",
        "microsoft support", "google support", "office 365", "microsoft 365",
    ],
    # 6. Scarcity / urgency: time pressure or threat to suppress deliberation.
    "scarcity": [
        "within 24 hours", "within 48 hours", "act now", "immediately",
        "urgent", "expires", "will expire", "will be locked", "will be suspended",
        "will be deactivated", "final notice", "last chance", "before it's too late",
        "limited time", "as soon as possible", "right away", "failure to",
        "avoid suspension", "account suspension", "time-sensitive", "deadline",
    ],
}

# Per-principle: how many distinct cue hits count as "fully present".
_SATURATION = 2


def _principle_score(hits: int) -> float:
    if hits <= 0:
        return 0.0
    return min(1.0, 0.6 + 0.4 * (hits - 1) / _SATURATION)  # 1 hit -> 0.6, 3+ -> 1.0


def detect_manipulation(text: str, **_) -> Signal:
    norm = normalize(text)

    fired: set[str] = set()
    per_principle: dict[str, float] = {}
    evidence: list[str] = []

    for principle, bank in PRINCIPLES.items():
        matched = [p for p in bank if p in norm]
        if matched:
            fired.add(principle)
            per_principle[principle] = _principle_score(len(matched))
            # Show at most two cue examples per principle to keep output readable.
            sample = ", ".join(f'"{m}"' for m in matched[:2])
            evidence.append(f"{principle.replace('_', ' ')}: {sample}")

    # The detector's own score is the strongest single tactic. The *stacking*
    # bonus (multiple tactics) is applied by the scoring engine, which owns the
    # cross-signal view (layered persuasion).
    base = max(per_principle.values(), default=0.0)

    return Signal(
        name="manipulation",
        category=Category.PSYCHOLOGY,
        score=base,
        weight=0.30,
        technique="Psychological manipulation tactics",
        evidence=evidence,
        principles=fired,
    )
