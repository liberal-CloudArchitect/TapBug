"""Versioned local VRT mapping and complete CVSS v3.1 vector inputs."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

VRT_SNAPSHOT_VERSION = "hermes-vrt-snapshot-2026-07-10"


class VrtClassification(BaseModel):
    snapshot_version: str
    category: str
    review_required: bool = True


_VRT_MAPPING = {
    "Security Misconfiguration": "server_security_misconfiguration.security_headers",
    "Information Disclosure": "server_security_misconfiguration.information_disclosure",
    "Broken Access Control": "broken_access_control.idor",
    "Broken Authentication": "broken_authentication_and_session_management.authentication_bypass",
}


def classify_vrt(vulnerability_class: str) -> VrtClassification:
    return VrtClassification(
        snapshot_version=VRT_SNAPSHOT_VERSION,
        category=_VRT_MAPPING.get(vulnerability_class, "other"),
    )


class CvssV31Input(BaseModel):
    """All base metrics must be supplied before a report can display a vector."""

    attack_vector: Literal["N", "A", "L", "P"]
    attack_complexity: Literal["L", "H"]
    privileges_required: Literal["N", "L", "H"]
    user_interaction: Literal["N", "R"]
    scope: Literal["U", "C"]
    confidentiality: Literal["N", "L", "H"]
    integrity: Literal["N", "L", "H"]
    availability: Literal["N", "L", "H"]

    @property
    def vector(self) -> str:
        return (
            "CVSS:3.1/"
            f"AV:{self.attack_vector}/AC:{self.attack_complexity}/PR:{self.privileges_required}/"
            f"UI:{self.user_interaction}/S:{self.scope}/C:{self.confidentiality}/"
            f"I:{self.integrity}/A:{self.availability}"
        )
