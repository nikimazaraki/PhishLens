"""AI-written-prose detector."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import Category, Signal
from ..text import sentences, words

IMPERATIVE_VERBS = {
    "click",
    "verify",
    "confirm",
    "update",
    "login",
    "log",
    "sign",
    "review",
    "submit",
    "provide",
    "enter",
    "reset",
    "download",
    "open",
    "complete",
    "validate",
    "authenticate",
    "reply",
    "contact",
    "call",
    "visit",
    "follow",
    "ensure",
    "act",
    "respond",
    "install",
    "enable",
    "authorize",
    "approve",
}


@runtime_checkable
class AuthorshipModel(Protocol):
    def score(self, text: str) -> tuple[float, list[str]]: ...


def _heuristic_score(text: str) -> tuple[float, list[str]]:
    sents = sentences(text)
    toks = words(text)
    evidence: list[str] = []

    if len(sents) < 2 or len(toks) < 12:
        return 0.0, []

    imperative_openers = sum(
        1 for s in sents if words(s) and words(s)[0].lower() in IMPERATIVE_VERBS
    )
    imp_density = imperative_openers / len(sents)

    lengths = [len(words(s)) for s in sents]
    mean_len = sum(lengths) / len(lengths)
    if mean_len > 0 and len(lengths) >= 3:
        variance = sum((x - mean_len) ** 2 for x in lengths) / len(lengths)
        cv = (variance**0.5) / mean_len
        uniformity = max(0.0, 1 - cv)
    else:
        uniformity = 0.0

    lowered = text.lower()
    sloppy_markers = [
        "!!",
        "!!!",
        " u ",
        " ur ",
        "kindly do the needful",
        "dear valued customer",
        "click here immediately!!",
    ]
    has_sloppiness = any(m in lowered for m in sloppy_markers)
    polish = 0.0 if has_sloppiness else 1.0

    if imp_density >= 0.34:
        evidence.append(
            f"high imperative-verb density ({imp_density:.0%} of sentences)"
        )
    if uniformity >= 0.6:
        evidence.append("uniform sentence length ('robotic professionalism')")
    if polish and (imp_density > 0 or uniformity >= 0.5):
        evidence.append("clean, error-free prose atypical of a cold request")

    score = 0.5 * min(1.0, imp_density / 0.5) + 0.3 * uniformity + 0.2 * polish
    if not evidence:
        score = 0.0
    return min(1.0, score), evidence


def detect_authorship(text: str, model: AuthorshipModel | None = None, **_) -> Signal:
    if model is not None:
        score, evidence = model.score(text)
    else:
        score, evidence = _heuristic_score(text)

    return Signal(
        name="authorship",
        category=Category.AUTHORSHIP,
        score=score,
        weight=0.12,
        technique="AI-generated / style-mimicking prose",
        evidence=evidence,
    )
