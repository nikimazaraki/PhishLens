"""Data models for PhishLens.

Every detector returns a `Signal`. Each Signal carries a `technique` label
naming, in plain terms, the attack technique the check counters, so a reviewer
can see the tool maps to real threats rather than arbitrary rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_PHISHING = "likely_phishing"
    HIGH_RISK = "high_risk"


class Category(str, Enum):
    """Groups signals by the kind of attack technique they detect."""

    PSYCHOLOGY = "psychology"          # persuasion / manipulation tactics
    OSINT = "osint"                    # targeted personalization
    AUTHORSHIP = "authorship"          # AI-generated prose
    PRETEXT = "pretext"                # fabricated scenarios
    INFRASTRUCTURE = "infrastructure"  # links, fake logins, QR, attachments
    SENDER = "sender"                  # spoofing, auth, lateral phishing


@dataclass
class Signal:
    """One detector's finding.

    score:     0.0 (clean) to 1.0 (strong evidence of the technique)
    weight:    relative contribution to the ensemble risk score
    evidence:  human-readable reasons the check fired (detectors explain *why*,
               not just classify)
    technique: plain-language name of the attack technique this check counters
    principles: for the manipulation detector, the distinct tactics that fired;
                used by the aggregator to score stacked persuasion
    """

    name: str
    category: Category
    score: float
    weight: float
    technique: str
    evidence: list[str] = field(default_factory=list)
    principles: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        # Clamp defensively so a buggy detector can't blow up the ensemble.
        self.score = max(0.0, min(1.0, float(self.score)))


@dataclass
class AnalysisResult:
    risk_score: float                 # 0-100
    verdict: Verdict
    signals: list[Signal]
    reasons: list[str]                # flat, ordered list of top evidence strings
    stacked_principles: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "risk_score": round(self.risk_score, 1),
            "verdict": self.verdict.value,
            "stacked_principles": sorted(self.stacked_principles),
            "signals": [
                {
                    "name": s.name,
                    "category": s.category.value,
                    "score": round(s.score, 3),
                    "weight": s.weight,
                    "technique": s.technique,
                    "evidence": s.evidence,
                    "principles": sorted(s.principles),
                }
                for s in self.signals
            ],
            "reasons": self.reasons,
        }
