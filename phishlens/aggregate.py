"""Ensemble scoring.

Combines the independent detector signals into a single 0-100 risk score plus a
verdict, and adds two *cross-signal* insights that no single detector can see on
its own:

1. Stacked persuasion. An email combining multiple manipulation tactics is far
   more dangerous than one using a single tactic — the pressure compounds. So
   the manipulation contribution escalates super-linearly with the number of
   distinct tactics that fired, something a linear keyword filter cannot express.

2. Complete con. The most effective lures are relevant (personalized), credible
   (look legitimate), and threatening (demand urgent action) all at once. This
   is a multiplicative meta-signal that is high only when all three legs are
   present, computed from the atomic detectors rather than re-parsing the text.
"""

from __future__ import annotations

from .detectors import DETECTORS
from .models import AnalysisResult, Category, Signal, Verdict


def _stacked_persuasion_bonus(principles: set[str]) -> tuple[float, str | None]:
    """Extra risk from co-occurring manipulation tactics.

    0-1 tactics: no bonus. Each additional distinct tactic adds risk with
    diminishing returns, capping the bonus so stacking cannot alone max the score.
    """
    n = len(principles)
    if n < 2:
        return 0.0, None
    # 2 -> 0.12, 3 -> 0.20, 4 -> 0.25, 5+ -> ~0.28
    bonus = min(0.28, 0.12 + 0.08 * (n - 2))
    note = (
        f"stacked persuasion: {n} manipulation tactics combined "
        f"({', '.join(sorted(principles))}) — layered pressure raises click risk"
    )
    return bonus, note


def _complete_con(signals: dict[str, Signal]) -> tuple[float, list[str]]:
    """Relevance x Credibility x Vulnerability, from atomic detectors."""
    relevance = signals["personalization"].score  # personalized targeting

    # Credibility = the email reads as legitimate/polished to the victim: clean
    # AI-style prose plus brand invocation.
    credibility = max(
        signals["authorship"].score,
        0.5 if signals["sender"].evidence else 0.0,
    )

    # Vulnerability = a call-to-action under threat/urgency.
    vulnerability = max(
        signals["manipulation"].score if "scarcity" in signals["manipulation"].principles else 0.0,
        signals["credential_harvest"].score,
        signals["pretext"].score * 0.8,
    )

    legs = {"relevance": relevance, "credibility": credibility, "vulnerability": vulnerability}
    present = [k for k, v in legs.items() if v >= 0.4]

    # Multiplicative: only meaningful when all three legs are non-trivial.
    triad = (relevance * credibility * vulnerability) ** (1 / 3) if all(legs.values()) else 0.0

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
    """Run every detector, combine into a risk score and explainable verdict.

    Recognized context kwargs (all optional):
        from_header, subject, claimed_brand,
        recipient_name, recipient_role, recipient_employer,
        headers={"spf","dkim","dmarc"}, links=[(display, href)],
        attachments=[filename], has_qr=bool, send_hour=int, model=AuthorshipModel
    """
    signals = [d(text, **context) for d in DETECTORS]
    by_name = {s.name: s for s in signals}

    # Base ensemble: weighted mean of signal scores (weights need not sum to 1;
    # we normalize by total weight so adding a detector does not rescale others).
    total_weight = sum(s.weight for s in signals) or 1.0
    base = sum(s.score * s.weight for s in signals) / total_weight

    # Cross-signal meta-signals.
    stack_bonus, stack_note = _stacked_persuasion_bonus(by_name["manipulation"].principles)
    triad_score, triad_notes = _complete_con(by_name)

    # Blend: base ensemble, plus additive stacked-persuasion bonus, plus a
    # modest pull toward a complete con. Clamp to [0, 1].
    combined = base + stack_bonus + 0.15 * triad_score
    combined = max(0.0, min(1.0, combined))
    risk_100 = round(combined * 100, 1)

    # Build the ordered, human-readable reason list (explain *why*, not just a score).
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
