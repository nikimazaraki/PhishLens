"""PhishLens - an explainable detector for AI-generated spear-phishing.

Each detector targets a specific hallmark of an AI-assisted phishing attack and
returns a score plus the evidence behind it, so the verdict is never a black box.
"""

from .aggregate import analyze
from .models import AnalysisResult, Category, Signal, Verdict

__version__ = "0.2.0"
__all__ = ["analyze", "AnalysisResult", "Signal", "Verdict", "Category"]
