"""Parent-owned, approval-free V4 discovery evidence for the local fixture."""

from __future__ import annotations

import hashlib
import json
import ssl
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .domain_contracts import canonical_digest
from .domain_contracts_v4 import RunPlanV4
from .evidence import EvidenceArtifactRef, EvidenceBinding, EvidenceStore, HeaderField
from .runtime import HttpRequest, PinnedHttpTransport, PolicyEngine, RunContext
from .runtime.agents import TaskEnvelope


class DiscoveryV4Error(RuntimeError):
    """A required local discovery observation could not be committed."""


def capture_discovery_v4(
    context: RunContext,
    plan: RunPlanV4,
    *,
    policy_engine: PolicyEngine,
    evidence_store: EvidenceStore,
    ca_file: Path,
) -> tuple[EvidenceArtifactRef, EvidenceArtifactRef]:
    """Capture exactly the recon target and mapper schema once, before approval.

    The two observations have action bindings but deliberately no campaign,
    approval, or consumption binding.  A prior committed pair is replayed only
    after strict parsing; it is never regenerated or overwritten.
    """

    relative = "discovery_v4/refs.json"
    stored = context.artifact_path(relative)
    if stored.is_file():
        try:
            raw = json.loads(stored.read_text(encoding="utf-8"))
            persisted_refs = tuple(
                EvidenceArtifactRef.model_validate(item) for item in raw["evidence"]
            )
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DiscoveryV4Error("persisted V4 discovery receipt is invalid") from exc
        if len(persisted_refs) != 2:
            raise DiscoveryV4Error("persisted V4 discovery receipt must contain two observations")
        for ref in persisted_refs:
            evidence_store.verify(ref)
        return persisted_refs[0], persisted_refs[1]

    transport = PinnedHttpTransport(ssl_context=ssl.create_default_context(cafile=str(ca_file)))
    destinations = (
        ("recon", "phase5-recon", plan.target),
        ("mapper", "phase5-mapper", "/openapi.json"),
    )
    refs: list[EvidenceArtifactRef] = []
    for role, task_id, destination in destinations:
        url = destination if destination.startswith("http") else urljoin(plan.target, destination)
        task = TaskEnvelope(
            version="4",
            run_id=context.run_id,
            task_id=task_id,
            role=role,
            scope_digest=context.scope_digest,
            payload={"operation": role, "run_plan_digest": plan.digest, "target": plan.target},
            request_budget=1,
            allowed_actions=("discovery_http_get",),
            evidence_required=True,
        )
        policy_engine.assert_automation()
        pinned = policy_engine.resolve_url(url)
        parsed = urlsplit(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        headers = {
            "Accept": "application/json, text/html",
            "Host": host if port in {80, 443} else f"{host}:{port}",
        }
        response = transport(
            HttpRequest(
                method="GET",
                url=url,
                connect_ip=pinned.connect_ip,
                host_header=headers["Host"],
                tls_server_name=host if parsed.scheme == "https" else None,
                headers=headers,
                body=b"",
                response_body_limit=policy_engine.policy.evidence_capture_max_bytes,
            )
        )
        action_id = f"discovery-{role}"
        action_digest = canonical_digest(
            {
                "run_id": context.run_id,
                "scope_digest": context.scope_digest,
                "action_id": action_id,
                "url": url,
            }
        )
        ref = evidence_store.capture(
            binding=EvidenceBinding(
                evidence_id=f"evidence-{role}-{hashlib.sha256(url.encode()).hexdigest()[:16]}",
                run_id=context.run_id,
                scope_digest=context.scope_digest,
                task_id=task_id,
                task_input_sha256=task.input_hash(),
                role=role,
                request_id=f"{task_id}:gateway:0",
                action_id=action_id,
                action_digest=action_digest,
                captured_at=datetime.now(UTC),
            ),
            request_method="GET",
            request_url=url,
            request_headers=tuple(HeaderField(name=k, value=v) for k, v in headers.items()),
            request_body=b"",
            response_status=response.status_code,
            response_headers=tuple(
                HeaderField(name=k, value=v)
                for k, v in (response.header_fields or tuple(response.headers.items()))
            ),
            response_body=response.body,
            response_was_truncated=response.truncated,
            response_original_bytes=response.original_body_bytes,
        )
        refs.append(ref)
    context.write_json(
        relative,
        {"plan_digest": plan.digest, "evidence": [ref.model_dump(mode="json") for ref in refs]},
        immutable=True,
    )
    return refs[0], refs[1]
