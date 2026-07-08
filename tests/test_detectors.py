"""Tests for PhishLens detectors and the ensemble.

Each detector is independently testable by design. These tests
also lock in the two cross-signal behaviors that make the tool a faithful
cross-signal behaviors: stacked persuasion and the complete-con signal.
"""

from phishlens import analyze, Verdict
from phishlens.detectors.psychology import detect_manipulation
from phishlens.detectors.authorship import detect_authorship, AuthorshipModel
from phishlens.detectors.infrastructure import (
    detect_links, detect_quishing, detect_attachments,
)
from phishlens.detectors.sender import detect_auth, detect_sender, detect_lateral


# --- psychology --------------------------------------------------------------

def test_manipulation_detects_each_tactic():
    s = detect_manipulation(
        "The IT department requires all employees to act now within 24 hours; "
        "you agreed to our updated terms and we have upgraded your account."
    )
    assert {"authority", "social_proof", "scarcity", "commitment", "reciprocation"} <= s.principles


def test_manipulation_empty_on_neutral_text():
    s = detect_manipulation("Here are my notes from the meeting. See you Friday.")
    assert s.score == 0.0
    assert s.principles == set()


def test_stacked_persuasion_beats_single_principle():
    single = analyze("This is urgent, please respond.")
    stacked = analyze(
        "The IT department requires all employees to act now within 24 hours. "
        "You agreed to the updated terms, and as a valued colleague we have "
        "upgraded your account on your behalf."
    )
    assert len(stacked.stacked_principles) >= 3
    assert stacked.risk_score > single.risk_score
    assert any("stacked persuasion" in r for r in stacked.reasons)


# --- authorship (with injectable model) --------------------------------------

def test_authorship_heuristic_flags_imperative_uniform_text():
    text = (
        "Verify your account today. Confirm your details now. "
        "Update your password here. Review the attached document."
    )
    s = detect_authorship(text)
    assert s.score > 0.0
    assert s.evidence


def test_authorship_accepts_injected_model():
    class FakeModel:
        def score(self, text):
            return 0.9, ["perplexity below human baseline"]

    assert isinstance(FakeModel(), AuthorshipModel)  # structural check
    s = detect_authorship("anything", model=FakeModel())
    assert s.score == 0.9
    assert "perplexity below human baseline" in s.evidence


# --- infrastructure ----------------------------------------------------------

def test_links_flags_ip_and_homograph_and_brand_subdomain():
    ip = detect_links("Log in at http://192.168.10.5/login now")
    assert ip.score >= 0.8

    brand = detect_links("Go to https://microsoft.secure-login.ru/sso")
    assert any("subdomain" in e for e in brand.evidence)


def test_links_display_href_mismatch():
    s = detect_links("click here", links=[("https://paypal.com", "https://evil.example/paypal")])
    assert s.score >= 0.8


def test_quishing_no_url_body():
    s = detect_quishing("Please scan the QR code below to verify your account.", has_qr=True)
    assert s.score >= 0.6
    assert s.evidence


def test_attachments_double_extension():
    s = detect_attachments("see attached", attachments=["invoice.pdf.exe"])
    assert s.score >= 0.9


# --- sender ------------------------------------------------------------------

def test_auth_dmarc_fail():
    s = detect_auth(headers={"spf": "pass", "dkim": "pass", "dmarc": "fail"})
    assert s.score >= 0.75


def test_sender_freemail_corporate_display():
    s = detect_sender(
        "Please update your details.",
        from_header='"IT Support Team" <helpdesk@gmail.com>',
        claimed_brand="Acme",
    )
    assert s.score >= 0.7


def test_lateral_reply_from_freemail():
    s = detect_lateral(
        "As we discussed, please confirm the payment.",
        subject="Re: Q3 invoice",
        from_header="external.person@gmail.com",
    )
    assert s.score >= 0.6


# --- end to end --------------------------------------------------------------

def test_benign_message_scores_low():
    r = analyze("Hi team, sharing my notes from the planning session. No rush.")
    assert r.verdict == Verdict.BENIGN
    assert r.risk_score < 20


def test_full_spear_phish_high_risk():
    r = analyze(
        "Hi Niki, as the new analyst at Deloitte, the IT department requires "
        "all employees to verify your account within 24 hours to avoid "
        "suspension. Sign in with Microsoft here: "
        "https://microsoft.login-verify.ru/sso",
        from_header='"IT Support" <it-support@gmail.com>',
        claimed_brand="Microsoft",
        recipient_name="Niki",
        recipient_role="analyst",
        recipient_employer="Deloitte",
        headers={"spf": "softfail", "dkim": "fail", "dmarc": "fail"},
    )
    assert r.verdict == Verdict.HIGH_RISK
    assert r.risk_score >= 70
    assert len(r.stacked_principles) >= 2
