"""Shared, dependency-free text utilities."""

from __future__ import annotations

import re

URL_RE = re.compile(
    r"""(?xi)
    \b(
        (?:https?://|www\.)\S+
        |
        [a-z0-9][a-z0-9\-]*\.[a-z]{2,}
        (?:/\S*)?
    )
    """,
)

SENTENCE_SPLIT_RE = re.compile(r"[.!?]+(?:\s+|$)")
WORD_RE = re.compile(r"[A-Za-z']+")


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def words(text: str) -> list[str]:
    return WORD_RE.findall(text)


def sentences(text: str) -> list[str]:
    parts = [s.strip() for s in SENTENCE_SPLIT_RE.split(text)]
    return [p for p in parts if p]


def extract_urls(text: str) -> list[str]:
    found = []
    for m in URL_RE.finditer(text):
        raw = m.group(1).rstrip(".,);:!?'\"")
        found.append(raw)
    return found


def count_matches(patterns: list[str], text_norm: str) -> list[str]:
    return [p for p in patterns if p in text_norm]


def saturating(count: int, full: int) -> float:
    if full <= 0:
        return 0.0
    return min(1.0, count / full)
