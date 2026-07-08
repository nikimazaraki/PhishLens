"""Malicious infrastructure and delivery-artifact detectors."""

from __future__ import annotations

import re

from ..models import Category, Signal
from ..text import extract_urls, normalize

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "tiny.cc",
}

BRAND_TOKENS = {
    "microsoft",
    "office365",
    "office",
    "outlook",
    "google",
    "gmail",
    "apple",
    "icloud",
    "amazon",
    "aws",
    "paypal",
    "netflix",
    "meta",
    "facebook",
    "linkedin",
    "dropbox",
    "docusign",
    "adobe",
    "instagram",
    "whatsapp",
}

IP_LITERAL_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}")
PUNYCODE_RE = re.compile(r"xn--", re.IGNORECASE)


def _host_of(url: str) -> str:
    u = re.sub(r"^\w+://", "", url)
    return u.split("/")[0].split("?")[0].lower()


def _has_mixed_scripts(host: str) -> bool:
    has_ascii = any("a" <= c <= "z" for c in host)
    has_non_ascii = any(ord(c) > 127 and c.isalpha() for c in host)
    return has_ascii and has_non_ascii


def detect_links(
    text: str,
    links: list[tuple[str, str]] | None = None,
    **_,
) -> Signal:
    evidence: list[str] = []
    score = 0.0

    urls = extract_urls(text)

    for url in urls:
        host = _host_of(url)

        if IP_LITERAL_RE.match(url):
            evidence.append(f"raw IP-address link ({host})")
            score = max(score, 0.8)

        if PUNYCODE_RE.search(host) or _has_mixed_scripts(host):
            evidence.append(f"possible homograph/punycode domain ({host})")
            score = max(score, 0.85)

        base = host[4:] if host.startswith("www.") else host
        if base in SHORTENERS or any(
            host.endswith("." + s) or host == s for s in SHORTENERS
        ):
            evidence.append(f"URL shortener hides destination ({host})")
            score = max(score, 0.6)

        labels = host.split(".")
        registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
        for brand in BRAND_TOKENS:
            if brand in host and brand not in registrable:
                evidence.append(
                    f'brand "{brand}" in subdomain of unrelated host ({host})'
                )
                score = max(score, 0.75)
                break
            if brand in url.lower().split(host, 1)[-1] and brand not in registrable:
                evidence.append(
                    f'brand "{brand}" in link path of unrelated host ({host})'
                )
                score = max(score, 0.6)
                break

    for display, href in links or []:
        d_urls = extract_urls(display)
        if d_urls:
            d_host = _host_of(d_urls[0])
            h_host = _host_of(href)
            if d_host and h_host and d_host not in h_host and h_host not in d_host:
                evidence.append(f"link text shows {d_host} but points to {h_host}")
                score = max(score, 0.85)

    return Signal(
        name="links",
        category=Category.INFRASTRUCTURE,
        score=score,
        weight=0.28,
        technique="Deceptive link / URL structure",
        evidence=evidence,
    )


def detect_credential_harvest(text: str, **_) -> Signal:
    norm = normalize(text)
    cues = [
        "sign in with microsoft",
        "sign in with google",
        "sign in with your",
        "log in to continue",
        "log in to confirm",
        "log in to verify",
        "enter your password",
        "enter your credentials",
        "confirm your password",
        "re-enter your password",
        "authenticate to continue",
        "session expired",
        "verify it's you",
        "verify it is you",
    ]
    matched = [c for c in cues if c in norm]
    score = 0.0 if not matched else min(0.85, 0.55 + 0.15 * (len(matched) - 1))
    evidence = [f'credential-request language: "{matched[0]}"'] if matched else []
    return Signal(
        name="credential_harvest",
        category=Category.INFRASTRUCTURE,
        score=score,
        weight=0.22,
        technique="Fake login / credential-harvest prompt",
        evidence=evidence,
    )


def detect_quishing(
    text: str,
    has_qr: bool | None = None,
    attachments: list[str] | None = None,
    **_,
) -> Signal:
    norm = normalize(text)
    evidence: list[str] = []
    score = 0.0

    qr_mentioned = any(
        k in norm for k in ["scan the qr", "scan this qr", "qr code", "scan to"]
    )
    qr_image = bool(has_qr)
    if attachments and not qr_image:
        qr_image = any(re.search(r"qr", a, re.IGNORECASE) for a in attachments)

    if qr_image or qr_mentioned:
        evidence.append(
            "QR-code call to action (bypasses URL scanners, shifts to mobile)"
        )
        score = 0.6
        if not extract_urls(text):
            evidence.append(
                "no in-body URL — interaction pushed entirely to the QR code"
            )
            score = 0.72

    return Signal(
        name="quishing",
        category=Category.INFRASTRUCTURE,
        score=score,
        weight=0.18,
        technique="QR-code phishing (scanner evasion)",
        evidence=evidence,
    )


RISKY_EXT = {
    ".docm",
    ".xlsm",
    ".pptm",
    ".htm",
    ".html",
    ".iso",
    ".img",
    ".vhd",
    ".js",
    ".vbs",
    ".hta",
    ".scr",
    ".zip",
    ".rar",
    ".7z",
    ".lnk",
}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx"}


def detect_attachments(text: str, attachments: list[str] | None = None, **_) -> Signal:
    if not attachments:
        return Signal(
            name="attachments",
            category=Category.INFRASTRUCTURE,
            score=0.0,
            weight=0.15,
            technique="Malicious attachment",
            evidence=[],
        )

    evidence: list[str] = []
    score = 0.0
    for name in attachments:
        lower = name.lower()
        ext = lower[lower.rfind(".") :] if "." in lower else ""
        if ext in RISKY_EXT:
            evidence.append(f"high-risk attachment type ({name})")
            score = max(score, 0.8)
        elif ext in DOC_EXT:
            evidence.append(
                f"document attachment — potential embedded link/script ({name})"
            )
            score = max(score, 0.4)
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.[a-z0-9]{2,4}$", lower):
            evidence.append(f"double-extension disguise ({name})")
            score = max(score, 0.9)

    return Signal(
        name="attachments",
        category=Category.INFRASTRUCTURE,
        score=score,
        weight=0.15,
        technique="Malicious attachment",
        evidence=evidence,
    )
