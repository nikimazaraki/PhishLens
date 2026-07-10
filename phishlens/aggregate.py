"""Ensemble scoring."""

from __future__ import annotations

from .detectors import DETECTORS
from .models import AnalysisResult, Signal, Verdict


def _stacked_persuasion_bonus(principles: set[str]) -> tuple[float, str | None]:
    n = len(principles)
    if n < 2:
        return 0.0, None
    bonus = min(0.28, 0.12 + 0.08 * (n - 2))
    note = (
        f"stacked persuasion: {n} manipulation tactics combined "
        f"({', '.join(sorted(principles))}) — layered pressure raises click risk"
    )
    return bonus, note


def _complete_con(signals: dict[str, Signal]) -> tuple[float, list[str]]:
    relevance = signals["personalization"].score

    credibility = max(
        signals["authorship"].score,
        0.5 if signals["sender"].evidence else 0.0,
    )

    vulnerability = max(
        signals["manipulation"].score
        if "scarcity" in signals["manipulation"].principles
        else 0.0,
        signals["credential_harvest"].score,
        signals["pretext"].score * 0.8,
    )

    legs = {
        "relevance": relevance,
        "credibility": credibility,
        "vulnerability": vulnerability,
    }
    present = [k for k, v in legs.items() if v >= 0.4]

    triad = (
        (relevance * credibility * vulnerability) ** (1 / 3)
        if all(legs.values())
        else 0.0
    )

    notes: list[str] = []
    if len(present) == 3:
        notes.append("complete con: relevant + credible + threatening all present")
    elif len(present) == 2:
        notes.append(f"partial con: {' + '.join(present)}")
    return triad, notes


def _verdict(score_100: float) -> Verdict:
    if score_100 >= 70:
        return Verdict.HIGH_RISK
    if score_100 >= 45:
        return Verdict.LIKELY_PHISHING
    if score_100 >= 20:
        return Verdict.SUSPICIOUS
    return Verdict.BENIGN


def analyze(text: str, **context) -> AnalysisResult:
    signals = [d(text, **context) for d in DETECTORS]
    by_name = {s.name: s for s in signals}

    # Detectors whose context (headers, from_header, attachments, ...) was
    # never supplied are excluded from the average rather than counted as a
    # confirmed-clean vote — otherwise every email is penalized by however
    # many metadata fields the caller happened not to pass in.
    scored_signals = [s for s in signals if s.applicable]
    total_weight = sum(s.weight for s in scored_signals) or 1.0
    base = sum(s.score * s.weight for s in scored_signals) / total_weight

    stack_bonus, stack_note = _stacked_persuasion_bonus(
        by_name["manipulation"].principles
    )
    triad_score, triad_notes = _complete_con(by_name)

    combined = base + stack_bonus + 0.15 * triad_score
    combined = max(0.0, min(1.0, combined))
    risk_100 = round(combined * 100, 1)

    reasons: list[str] = []
    if stack_note:
        reasons.append(stack_note)
    reasons.extend(triad_notes)
    for s in sorted(signals, key=lambda x: x.score * x.weight, reverse=True):
        for e in s.evidence:
            reasons.append(f"[{s.name}] {e}")

    return AnalysisResult(
        risk_score=risk_100,
        verdict=_verdict(risk_100),
        signals=signals,
        reasons=reasons,
        stacked_principles=by_name["manipulation"].principles,
    )
