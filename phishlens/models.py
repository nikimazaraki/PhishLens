"""Data models for PhishLens."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_PHISHING = "likely_phishing"
    HIGH_RISK = "high_risk"


class Category(str, Enum):
    PSYCHOLOGY = "psychology"
    OSINT = "osint"
    AUTHORSHIP = "authorship"
    PRETEXT = "pretext"
    INFRASTRUCTURE = "infrastructure"
    SENDER = "sender"


@dataclass
class Signal:
    name: str
    category: Category
    score: float
    weight: float
    technique: str
    evidence: list[str] = field(default_factory=list)
    principles: set[str] = field(default_factory=set)
    # False when the detector's required context (headers, from_header,
    # attachments, send_hour, ...) was never supplied. Distinguishes "checked
    # and found nothing" from "couldn't check" so a missing signal doesn't get
    # averaged in as evidence of safety.
    applicable: bool = True

    def __post_init__(self) -> None:
        self.score = max(0.0, min(1.0, float(self.score)))


@dataclass
class AnalysisResult:
    risk_score: float
    verdict: Verdict
    signals: list[Signal]
    reasons: list[str]
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
