"""Fabricated-scenario / pretext detector."""

from __future__ import annotations

from ..models import Category, Signal
from ..text import normalize

SCENARIOS: dict[str, list[str]] = {
    "it_security_reset": [
        "password reset",
        "reset your password",
        "mfa",
        "multi-factor",
        "two-factor",
        "2fa",
        "re-authenticate",
        "reauthenticate",
        "verify your account",
        "unusual sign-in",
        "unusual login",
        "new device login",
        "security alert",
        "confirm your credentials",
        "mailbox is full",
        "storage limit",
        "revalidate your account",
    ],
    "financial_incentive": [
        "bonus",
        "tax refund",
        "tax rebate",
        "you are owed",
        "reimbursement",
        "payroll update",
        "salary adjustment",
        "gift card",
        "you've won",
        "you have won",
        "claim your",
        "outstanding payment to you",
    ],
    "invoice_bec": [
        "invoice",
        "outstanding invoice",
        "payment overdue",
        "wire transfer",
        "update banking details",
        "change payment",
        "remittance",
        "purchase order",
        "approve payment",
        "vendor payment",
        "past due",
    ],
    "delivery_parcel": [
        "package could not be delivered",
        "delivery failed",
        "parcel is waiting",
        "shipping fee",
        "customs fee",
        "track your package",
        "redelivery",
    ],
    "software_update": [
        "software update",
        "mandatory update",
        "update your device",
        "install the update",
        "download the update",
        "update file is attached",
        "update file attached",
        "required system update",
    ],
}


def detect_pretext(text: str, **_) -> Signal:
    norm = normalize(text)
    fired: list[str] = []
    evidence: list[str] = []

    for scenario, cues in SCENARIOS.items():
        matched = [c for c in cues if c in norm]
        if matched:
            fired.append(scenario)
            evidence.append(f'{scenario.replace("_", " ")} pretext: "{matched[0]}"')

    if not fired:
        score = 0.0
    else:
        score = 0.65 if len(fired) == 1 else 0.85

    return Signal(
        name="pretext",
        category=Category.PRETEXT,
        score=score,
        weight=0.18,
        technique="Fabricated pretext scenario",
        evidence=evidence,
    )
