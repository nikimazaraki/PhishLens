"""Sender-side detectors.

  - auth:      SPF / DKIM / DMARC results, when headers are supplied.
  - sender:    brand display-name from a free-mail domain, body-vs-domain
               mismatch, lookalike/typosquat domains.
  - lateral:   thread-hijacking tells - a "Re:" reply from an external free-mail
               sender, or an internal-sounding request whose sender domain does
               not match the claimed organization.
  - temporal:  send-time inside the 09:00-11:00 window when recipients skim on
               autopilot and open rates peak. Weak, corroborating.
"""

from __future__ import annotations

import re

from ..models import Category, Signal
from ..text import normalize

FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "outlook.com",
    "hotmail.com", "live.com", "aol.com", "protonmail.com", "proton.me",
    "icloud.com", "mail.com", "gmx.com", "yandex.com", "zoho.com",
}

_ADDR_RE = re.compile(r"<?([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})>?")
_DISPLAY_RE = re.compile(r'^\s*"?([^"<]+?)"?\s*<')


def _parse_from(from_header: str) -> tuple[str, str, str]:
    """Return (display_name, email, domain) from a From header, best-effort."""
    display = ""
    m = _DISPLAY_RE.match(from_header or "")
    if m:
        display = m.group(1).strip()
    email = ""
    a = _ADDR_RE.search(from_header or "")
    if a:
        email = a.group(1).lower()
    domain = email.split("@", 1)[1] if "@" in email else ""
    return display, email, domain


def detect_auth(text: str | None = None, headers: dict | None = None, **_) -> Signal:
    """SPF/DKIM/DMARC. Only meaningful when the caller supplies parsed headers."""
    if not headers:
        return Signal(
            name="auth", category=Category.SENDER, score=0.0, weight=0.20,
            technique="Sender authentication failure (SPF/DKIM/DMARC)", evidence=[],
        )
    evidence: list[str] = []
    score = 0.0
    for mech in ("spf", "dkim", "dmarc"):
        val = str(headers.get(mech, "")).lower()
        if val in ("fail", "softfail", "none", "temperror", "permerror"):
            evidence.append(f"{mech.upper()} = {val}")
            # DMARC failure is the most decisive of the three.
            score = max(score, 0.75 if mech == "dmarc" else 0.6)
    return Signal(
        name="auth", category=Category.SENDER, score=score, weight=0.20,
        technique="Sender authentication failure (SPF/DKIM/DMARC)", evidence=evidence,
    )


def _lookalike(domain: str, claimed_brand: str | None) -> bool:
    """Cheap typosquat check: brand token appears but domain is not the brand's
    real registrable domain (e.g. 'micros0ft.com', 'paypal-secure.com')."""
    if not claimed_brand:
        return False
    brand = claimed_brand.lower().replace(" ", "")
    core = domain.split(".")[0] if domain else ""
    if not core:
        return False
    # brand embedded with extra chars, or a single-character substitution.
    if brand in core and core != brand:
        return True
    if len(core) == len(brand) and sum(a != b for a, b in zip(core, brand)) == 1:
        return True
    return False


def detect_sender(
    text: str,
    from_header: str | None = None,
    claimed_brand: str | None = None,
    **_,
) -> Signal:
    if not from_header:
        return Signal(
            name="sender", category=Category.SENDER, score=0.0, weight=0.18,
            technique="Sender spoofing / brand impersonation", evidence=[],
        )

    display, email, domain = _parse_from(from_header)
    evidence: list[str] = []
    score = 0.0

    # A brand/authority display name sent from a free consumer mailbox.
    if domain in FREE_MAIL and display:
        looks_corporate = any(
            k in display.lower()
            for k in ["support", "it", "team", "security", "admin", "hr",
                      "service", "notification", "no-reply", "help"]
        ) or (claimed_brand and claimed_brand.lower() in display.lower())
        if looks_corporate:
            evidence.append(f'corporate display name "{display}" from free-mail ({domain})')
            score = max(score, 0.75)

    if _lookalike(domain, claimed_brand):
        evidence.append(f'lookalike/typosquat domain for "{claimed_brand}" ({domain})')
        score = max(score, 0.85)

    # Claimed brand in the body but sender domain unrelated to it.
    if claimed_brand:
        b = claimed_brand.lower().replace(" ", "")
        if b in normalize(text) and domain and b not in domain:
            evidence.append(f'body invokes "{claimed_brand}" but sender domain is {domain}')
            score = max(score, 0.6)

    return Signal(
        name="sender", category=Category.SENDER, score=score, weight=0.18,
        technique="Sender spoofing / lookalike domain", evidence=evidence,
    )


def detect_lateral(
    text: str,
    subject: str | None = None,
    from_header: str | None = None,
    claimed_brand: str | None = None,
    **_,
) -> Signal:
    """Thread-hijacking / lateral-phishing tells.

    Lateral phishing is dangerous precisely because it looks internal. From an
    email alone we can only flag *inconsistencies*: a reply ('Re:') that arrives
    from an external free-mail address, or internal-action language ('as we
    discussed', 'per our thread') paired with an off-domain sender.
    """
    _, _, domain = _parse_from(from_header or "")
    norm = normalize(text)
    evidence: list[str] = []
    score = 0.0

    is_reply = bool(subject) and re.match(r"\s*(re|fwd?)\s*:", subject, re.IGNORECASE)
    internal_cues = [
        "as we discussed", "per our thread", "following up on our",
        "as per our conversation", "the document i mentioned",
        "as agreed in our call", "continuing our thread",
    ]
    has_internal_cue = any(c in norm for c in internal_cues)

    if is_reply and domain in FREE_MAIL:
        evidence.append(f"reply/forward from an external free-mail sender ({domain})")
        score = max(score, 0.7)
    if has_internal_cue and domain in FREE_MAIL:
        evidence.append("internal-thread language from an external mailbox")
        score = max(score, 0.65)

    return Signal(
        name="lateral", category=Category.SENDER, score=score, weight=0.14,
        technique="Thread hijacking / lateral phishing", evidence=evidence,
    )


def detect_temporal(text: str | None = None, send_hour: int | None = None, **_) -> Signal:
    """Send-time in the 09:00-11:00 window when recipients skim on autopilot.

    A genuinely weak signal on its own; included for completeness and
    weighted accordingly. Only fires when the caller supplies a send hour.
    """
    if send_hour is None:
        return Signal(
            name="temporal", category=Category.SENDER, score=0.0, weight=0.05,
            technique="Send-time optimization", evidence=[],
        )
    in_window = 9 <= int(send_hour) < 11
    return Signal(
        name="temporal", category=Category.SENDER,
        score=0.3 if in_window else 0.0, weight=0.05,
        technique="Send-time optimization",
        evidence=["sent in the 09:00-11:00 cognitive-triage window"] if in_window else [],
    )
