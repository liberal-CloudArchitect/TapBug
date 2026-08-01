"""Runtime selection gate for governed capability wheels."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .models import WheelManifest
from .registry import WheelRegistry, WheelRegistryError


class RuntimeSelector:
    """Select only an active, profile-authorized, untampered capability wheel."""

    def __init__(self, registry: WheelRegistry, *, profile: str) -> None:
        if not profile:
            raise ValueError("profile must be non-empty")
        self._registry = registry
        self._profile = profile

    @property
    def registry(self) -> WheelRegistry:
        """Expose the governed registry to CapabilityHost, not artifact code."""
        return self._registry

    def select(
        self,
        wheel_id: str,
        version: str,
        *,
        artifact_root: Path,
        required_capability: str | None = None,
        now: datetime | None = None,
    ) -> WheelManifest:
        """Return a selected manifest only after lifecycle/profile/hash checks."""
        manifest = self._registry.select(
            wheel_id,
            version,
            profile=self._profile,
            artifact_root=artifact_root,
            now=now,
        )
        if required_capability is not None and required_capability not in manifest.capabilities:
            raise WheelRegistryError("wheel does not declare the required capability")
        return manifest
