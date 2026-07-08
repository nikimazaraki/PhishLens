"""Detector registry."""

from .authorship import detect_authorship
from .infrastructure import (
    detect_attachments,
    detect_credential_harvest,
    detect_links,
    detect_quishing,
)
from .osint import detect_personalization
from .pretext import detect_pretext
from .psychology import detect_manipulation
from .sender import (
    detect_auth,
    detect_lateral,
    detect_sender,
    detect_temporal,
)

DETECTORS = [
    detect_manipulation,
    detect_personalization,
    detect_authorship,
    detect_pretext,
    detect_links,
    detect_credential_harvest,
    detect_quishing,
    detect_attachments,
    detect_auth,
    detect_sender,
    detect_lateral,
    detect_temporal,
]

__all__ = ["DETECTORS"]
