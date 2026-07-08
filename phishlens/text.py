"""Shared, dependency-free text utilities.

Kept deliberately small and pure so every detector can be unit-tested in
isolation. An ensemble of independent checks is more robust than a single
monolithic classifier.
"""

from __future__ import annotations

import re

# A URL matcher permissive enough to catch obfuscated links but anchored on a
# scheme or a bare domain-with-TLD so we do not match every dotted token.
URL_RE = re.compile(
    r"""(?xi)
    \b(
        (?:https?://|www\.)\S+           # explicit scheme or www.
        |
        [a-z0-9][a-z0-9\-]*\.[a-z]{2,}   # bare domain like login.example.co
        (?:/\S*)?
    )
    """,
)

SENTENCE_SPLIT_RE = re.compile(r"[.!?]+(?:\s+|$)")
WORD_RE = re.compile(r"[A-Za-z']+")


def normalize(text: str) -> str:
    """Lowercase and collapse whitespace for keyword matching."""
    return re.sub(r"\s+", " ", text.lower()).strip()


def words(text: str) -> list[str]:
    return WORD_RE.findall(text)


def sentences(text: str) -> list[str]:
    """Naive sentence splitter — good enough for stylometry heuristics."""
    parts = [s.strip() for s in SENTENCE_SPLIT_RE.split(text)]
    return [p for p in parts if p]


def extract_urls(text: str) -> list[str]:
    """Return raw URL-like substrings, trimming trailing punctuation."""
    found = []
    for m in URL_RE.finditer(text):
        raw = m.group(1).rstrip(".,);:!?'\"")
        found.append(raw)
    return found


def count_matches(patterns: list[str], text_norm: str) -> list[str]:
    """Return the subset of `patterns` (plain substrings) present in text.

    `patterns` are treated as substrings, not regexes, so callers can pass
    natural phrases like "act now" without escaping.
    """
    return [p for p in patterns if p in text_norm]


def saturating(count: int, full: int) -> float:
    """Map a hit count to 0..1 that saturates at `full` hits.

    Used so that, e.g., 3 urgency phrases and 6 urgency phrases both read as
    "strong" rather than letting one noisy category dominate linearly.
    """
    if full <= 0:
        return 0.0
    return min(1.0, count / full)
