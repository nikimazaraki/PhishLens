"""AI-written-prose detector.

Machine-generated lures have a signature that flips the classic red flags.
Old spam was caught by typos and bad grammar; AI lures exhibit the opposite -
"robotic professionalism": clean grammar, uniform sentence structure, high
imperative-verb density, and a consistently formal tone. Under AI, suspiciously
polished text becomes a signal *for* suspicion, not against it.

Stylometry is inherently fragile: a model can be prompted to vary its
complexity to mimic a human baseline. So this signal is deliberately weighted
as corroborating, not decisive, and is built behind an `AuthorshipModel`
protocol - the heuristic below is the default, and an ML/perplexity or
LLM-as-judge backend can be injected without touching any other detector.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import Category, Signal
from ..text import sentences, words

# Verbs that commonly open an imperative sentence in phishing CTAs. Elevated
# imperative-verb usage is a stylometric marker of machine-generated text.
IMPERATIVE_VERBS = {
    "click", "verify", "confirm", "update", "login", "log", "sign", "review",
    "submit", "provide", "enter", "reset", "download", "open", "complete",
    "validate", "authenticate", "reply", "contact", "call", "visit", "follow",
    "ensure", "act", "respond", "install", "enable", "authorize", "approve",
}


@runtime_checkable
class AuthorshipModel(Protocol):
    """Injectable backend for machine-authorship scoring.

    Return (score in 0..1, list of evidence strings). Implement this with a
    local perplexity/stylometry model or an LLM-as-judge call and pass it to
    `detect_authorship(..., model=...)` to upgrade the signal.
    """

    def score(self, text: str) -> tuple[float, list[str]]: ...


def _heuristic_score(text: str) -> tuple[float, list[str]]:
    sents = sentences(text)
    toks = words(text)
    evidence: list[str] = []

    if len(sents) < 2 or len(toks) < 12:
        # Too short to say anything stylometric with any confidence.
        return 0.0, []

    # 1. Imperative-verb density: fraction of sentences that open with a
    #    command verb. High density is a documented AI-CTA marker.
    imperative_openers = sum(
        1 for s in sents if words(s) and words(s)[0].lower() in IMPERATIVE_VERBS
    )
    imp_density = imperative_openers / len(sents)

    # 2. Sentence-length uniformity: LLM prose tends to be evenly measured.
    #    Low coefficient of variation in sentence length -> "robotic" regularity.
    lengths = [len(words(s)) for s in sents]
    mean_len = sum(lengths) / len(lengths)
    if mean_len > 0 and len(lengths) >= 3:
        variance = sum((x - mean_len) ** 2 for x in lengths) / len(lengths)
        cv = (variance ** 0.5) / mean_len  # coefficient of variation
        uniformity = max(0.0, 1 - cv)      # cv=0 -> perfectly uniform -> 1.0
    else:
        uniformity = 0.0

    # 3. Polish: absence of the classic low-effort red flags (typos, sloppiness).
    #    Clean text is now *more* suspicious in an unsolicited cold message.
    lowered = text.lower()
    sloppy_markers = ["!!", "!!!", " u ", " ur ", "kindly do the needful",
                      "dear valued customer", "click here immediately!!"]
    has_sloppiness = any(m in lowered for m in sloppy_markers)
    polish = 0.0 if has_sloppiness else 1.0

    if imp_density >= 0.34:
        evidence.append(f"high imperative-verb density ({imp_density:.0%} of sentences)")
    if uniformity >= 0.6:
        evidence.append("uniform sentence length ('robotic professionalism')")
    if polish and (imp_density > 0 or uniformity >= 0.5):
        evidence.append("clean, error-free prose atypical of a cold request")

    # Weighted blend. Imperative density is the strongest single marker.
    score = 0.5 * min(1.0, imp_density / 0.5) + 0.3 * uniformity + 0.2 * polish
    # Only surface the signal if at least one concrete marker tripped.
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
        weight=0.12,  # corroborating, not decisive (stylometry is easy to evade)
        technique="AI-generated / style-mimicking prose",
        evidence=evidence,
    )
