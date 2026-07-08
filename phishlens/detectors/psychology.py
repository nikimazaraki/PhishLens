"""Psychological manipulation tactics."""

from __future__ import annotations

from ..models import Category, Signal
from ..text import normalize

PRINCIPLES: dict[str, list[str]] = {
    "reciprocation": [
        "we have upgraded", "we've upgraded", "we have improved", "as a courtesy",
        "free of charge", "complimentary", "we've credited", "we have added",
        "on your behalf", "we've secured your", "we have secured your",
        "as a thank you", "we've enabled", "we have enabled",
    ],
    "commitment": [
        "you agreed", "as you requested", "as requested", "per your request",
        "you signed up", "you registered", "you enrolled", "as agreed",
        "updated terms", "terms and conditions", "policy violation",
        "you recently", "to remain compliant", "as per our agreement",
    ],
    "social_proof": [
        "all customers", "all employees", "all users", "all staff",
        "company-wide", "everyone", "most users", "others have already",
        "your colleagues", "join thousands", "mandatory for all",
        "new company policy", "all account holders",
    ],
    "liking": [
        "great work", "as a valued", "we appreciate you", "hope you're well",
        "hope you are well", "it was great to", "loved your", "impressed by your",
        "as one of our best", "your recent success",
    ],
    "authority": [
        "it department", "it support", "help desk", "helpdesk", "system administrator",
        "administrator", "security team", "compliance team", "compliance department",
        "hr department", "human resources", "legal department", "chief executive",
        "ceo", "cfo", "on behalf of management", "official notice",
        "verify your identity", "your bank", "account security team",
        "microsoft support", "google support", "office 365", "microsoft 365",
    ],
    "scarcity": [
        "within 24 hours", "within 48 hours", "act now", "immediately",
        "urgent", "expires", "will expire", "will be locked", "will be suspended",
        "will be deactivated", "final notice", "last chance", "before it's too late",
        "limited time", "as soon as possible", "right away", "failure to",
        "avoid suspension", "account suspension", "time-sensitive", "deadline",
    ],
}

_SATURATION = 2


def _principle_score(hits: int) -> float:
    if hits <= 0:
        return 0.0
    return min(1.0, 0.6 + 0.4 * (hits - 1) / _SATURATION)


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
            sample = ", ".join(f'"{m}"' for m in matched[:2])
            evidence.append(f"{principle.replace('_', ' ')}: {sample}")

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
