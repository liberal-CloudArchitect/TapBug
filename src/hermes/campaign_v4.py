"""Parent-owned fixed verification campaign for localhost-only V4 runs.

V4 keeps the V3 trust boundary: branch agents may propose observations, but the
trusted runtime is the only authority that may freeze candidate graphs into the
exact action campaign presented for human approval.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Literal
from urllib.parse import urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain_contracts import canonical_digest

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"
_URL = r"^https?://localhost:[0-9]+(?:/.*)?$"

CandidateTypeV4 = Literal[
    "missing_x_content_type_options",
    "exposed_debug_endpoint",
    "unauthorized_graphql_mutation",
    "privilege_escalation",
    "insecure_session_cookie",
    "cross_tenant_object_read",
    "unvalidated_redirect",
    "workflow_transition_bypass",
]
RiskGroupV4 = Literal["readonly", "mutation", "cleanup"]
ActionPurposeV4 = Literal[
    "baseline",
    "candidate",
    "negative_control",
    "cleanup",
    "cleanup_check",
]

_CANDIDATE_ORDER: tuple[CandidateTypeV4, ...] = (
    "missing_x_content_type_options",
    "exposed_debug_endpoint",
    "unauthorized_graphql_mutation",
    "privilege_escalation",
    "insecure_session_cookie",
    "cross_tenant_object_read",
    "unvalidated_redirect",
    "workflow_transition_bypass",
)


def _unique(values: Sequence[str], label: str) -> tuple[str, ...]:
    items = tuple(values)
    if len(items) != len(set(items)):
        raise ValueError(f"{label} must be unique")
    return items


def _aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value


def _body_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json_digest(value: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


class CampaignV4Error(RuntimeError):
    """Trusted V4 campaign inputs could not produce a safe fixed action graph."""


class VerificationActionV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["4"] = "4"
    action_id: str = Field(pattern=_ID)
    candidate_id: str = Field(pattern=_ID)
    candidate_type: CandidateTypeV4
    candidate_consumers: tuple[str, ...] = Field(min_length=1)
    purpose: ActionPurposeV4
    risk_group: RiskGroupV4
    action_kind: Literal["validation_http_get", "validation_http_request"]
    method: Literal["GET", "POST"]
    target_url: str = Field(pattern=_URL)
    action_digest: str = Field(pattern=_DIGEST)
    request_budget: int = Field(default=1, ge=1, le=1)
    identity_alias: str | None = Field(default=None, pattern=_ID)
    identity_binding_digest: str | None = Field(default=None, pattern=_DIGEST)
    body_sha256: str = Field(pattern=_DIGEST)
    follow_redirects: bool = True
    depends_on: tuple[str, ...] = ()
    cleanup_of: str | None = Field(default=None, pattern=_ID)

    @field_validator("candidate_consumers", "depends_on")
    @classmethod
    def unique_lists(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "campaign action collections")

    @model_validator(mode="after")
    def coherent_action(self) -> VerificationActionV4:
        expected_kind = "validation_http_get" if self.method == "GET" else "validation_http_request"
        if self.action_kind != expected_kind:
            raise ValueError("action kind must match the HTTP method")
        if self.identity_alias is None and self.identity_binding_digest is not None:
            raise ValueError("identity binding digest requires an identity alias")
        if self.identity_alias is not None and self.identity_binding_digest is None:
            raise ValueError("identity alias requires an identity binding digest")
        if self.purpose in {"cleanup", "cleanup_check"} and self.risk_group != "mutation":
            raise ValueError("cleanup nodes remain mutation actions in the canonical campaign")
        if self.cleanup_of is not None and self.purpose not in {"cleanup", "cleanup_check"}:
            raise ValueError("only cleanup nodes may point at a forward action")
        return self


class VerificationCampaignPlanV4(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["4"] = "4"
    run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    generated_by_task_id: str = Field(pattern=_ID)
    campaign_id: str = Field(pattern=_ID)
    actions: tuple[VerificationActionV4, ...]
    discovery_request_budget: int = Field(default=2, ge=2, le=2)
    request_budget: int = Field(ge=0, le=26)
    created_at: datetime
    expires_at: datetime

    @field_validator("created_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _aware(value, "campaign timestamp")

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    @property
    def total_request_budget(self) -> int:
        return self.discovery_request_budget + self.request_budget

    @model_validator(mode="after")
    def coherent_campaign(self) -> VerificationCampaignPlanV4:
        if self.expires_at <= self.created_at:
            raise ValueError("campaign must expire after creation")
        action_ids = _unique(tuple(item.action_id for item in self.actions), "campaign action IDs")
        _unique(tuple(item.action_digest for item in self.actions), "campaign action digests")
        known = set(action_ids)
        if self.request_budget != sum(item.request_budget for item in self.actions):
            raise ValueError("campaign request budget must equal action budgets")
        # A full V4 local-lab run has 26 governed actions plus the two
        # discovery observations.  A branch-isolated run deliberately carries
        # only the action subgraphs whose assessments succeeded, so its budget
        # is smaller but must still remain within the frozen global ceiling.
        if not self.actions:
            raise ValueError("V4 campaign must contain at least one approved action")
        if self.total_request_budget > 28:
            raise ValueError("V4 localhost campaign exceeds its 28-request ceiling")
        for action in self.actions:
            if any(item not in known for item in action.depends_on):
                raise ValueError("campaign dependency escapes the action graph")
            if action.cleanup_of is not None and action.cleanup_of not in known:
                raise ValueError("cleanup target escapes the action graph")
            if action.action_id in action.depends_on:
                raise ValueError("action cannot depend on itself")
        return self


def campaign_candidate_ids(campaign: VerificationCampaignPlanV4) -> tuple[str, ...]:
    return tuple(
        candidate_id
        for candidate_id, _ in sorted(
            {
                action.candidate_id: _CANDIDATE_ORDER.index(action.candidate_type)
                for action in campaign.actions
            }.items(),
            key=lambda item: item[1],
        )
    )


def approval_actions_v4(
    campaign: VerificationCampaignPlanV4, risk_group: RiskGroupV4
) -> tuple[VerificationActionV4, ...]:
    if risk_group == "cleanup":
        return tuple(
            action for action in campaign.actions if action.purpose in {"cleanup", "cleanup_check"}
        )
    return tuple(action for action in campaign.actions if action.risk_group == risk_group)


def build_verification_campaign_v4(
    *,
    run_id: str,
    scope_digest: str,
    generated_by_task_id: str,
    endpoint_base: str,
    identity_binding_digests: Mapping[str, str],
    created_at: datetime,
    expires_at: datetime,
    campaign_id: str = "phase5-campaign",
    candidate_types: Sequence[CandidateTypeV4] | None = None,
) -> VerificationCampaignPlanV4:
    if not endpoint_base.startswith(("http://localhost:", "https://localhost:")):
        raise CampaignV4Error("V4 campaign base must be a localhost URL")
    parsed_base = urlsplit(endpoint_base)
    if (
        parsed_base.scheme not in {"http", "https"}
        or parsed_base.hostname != "localhost"
        or parsed_base.port is None
        or parsed_base.username is not None
        or parsed_base.password is not None
    ):
        raise CampaignV4Error("V4 campaign base must be a canonical localhost origin")
    # The CLI target is deliberately a concrete teaching-fixture entry point
    # (normally ``/candidate``), not an origin.  Campaign paths must remain
    # rooted at the verified origin; joining them against the target path made
    # every approved action request ``/candidate/<route>`` and silently turned
    # the fixture proofs into 404 observations.
    origin = urlunsplit((parsed_base.scheme, parsed_base.netloc, "", "", ""))
    required_aliases = {"alice", "bob", "fixture-admin"}
    missing = sorted(alias for alias in required_aliases if alias not in identity_binding_digests)
    if missing:
        raise CampaignV4Error(f"missing required V4 identity aliases: {', '.join(missing)}")

    enabled = tuple(candidate_types or _CANDIDATE_ORDER)
    if not enabled:
        raise CampaignV4Error("V4 campaign requires at least one candidate type")
    if len(enabled) != len(set(enabled)):
        raise CampaignV4Error("V4 campaign candidate types must be unique")
    unknown = set(enabled) - set(_CANDIDATE_ORDER)
    if unknown:
        raise CampaignV4Error("V4 campaign contains an unknown candidate type")
    enabled_set = set(enabled)

    actions: list[VerificationActionV4] = []

    def add(
        *,
        action_id: str,
        candidate_id: str,
        candidate_type: CandidateTypeV4,
        purpose: ActionPurposeV4,
        risk_group: RiskGroupV4,
        method: Literal["GET", "POST"],
        path: str,
        query: Mapping[str, str] | None = None,
        body: object | None = None,
        identity_alias: str | None = None,
        depends_on: Sequence[str] = (),
        cleanup_of: str | None = None,
        follow_redirects: bool = True,
    ) -> VerificationActionV4 | None:
        if candidate_type not in enabled_set:
            return None
        base = origin + "/" + path.lstrip("/")
        if query:
            base = base + ("&" if "?" in base else "?") + urlencode(sorted(query.items()))
        body_bytes = b""
        if body is not None:
            body_bytes = json.dumps(
                body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode()
        digest_input = {
            "run_id": run_id,
            "scope_digest": scope_digest,
            "action_id": action_id,
            "candidate_id": candidate_id,
            "candidate_type": candidate_type,
            "purpose": purpose,
            "risk_group": risk_group,
            "method": method,
            "target_url": base,
            "identity_alias": identity_alias,
            "identity_binding_digest": identity_binding_digests.get(identity_alias)
            if identity_alias
            else None,
            "body_sha256": _body_digest(body_bytes),
            "follow_redirects": follow_redirects,
            "depends_on": tuple(depends_on),
            "cleanup_of": cleanup_of,
        }
        action = VerificationActionV4(
            action_id=action_id,
            candidate_id=candidate_id,
            candidate_type=candidate_type,
            candidate_consumers=(candidate_id,),
            purpose=purpose,
            risk_group=risk_group,
            action_kind="validation_http_get" if method == "GET" else "validation_http_request",
            method=method,
            target_url=base,
            action_digest=_json_digest(digest_input),
            identity_alias=identity_alias,
            identity_binding_digest=identity_binding_digests.get(identity_alias)
            if identity_alias
            else None,
            body_sha256=_body_digest(body_bytes),
            follow_redirects=follow_redirects,
            depends_on=tuple(depends_on),
            cleanup_of=cleanup_of,
        )
        actions.append(action)
        return action

    # Read-only verification families.
    add(
        action_id="web-xcto-target",
        candidate_id="web-xcto",
        candidate_type="missing_x_content_type_options",
        purpose="candidate",
        risk_group="readonly",
        method="GET",
        path="/candidate",
    )
    add(
        action_id="web-xcto-control",
        candidate_id="web-xcto",
        candidate_type="missing_x_content_type_options",
        purpose="negative_control",
        risk_group="readonly",
        method="GET",
        path="/control",
    )
    add(
        action_id="infra-debug-target",
        candidate_id="infra-debug",
        candidate_type="exposed_debug_endpoint",
        purpose="candidate",
        risk_group="readonly",
        method="GET",
        path="/debug",
    )
    add(
        action_id="infra-debug-control",
        candidate_id="infra-debug",
        candidate_type="exposed_debug_endpoint",
        purpose="negative_control",
        risk_group="readonly",
        method="GET",
        path="/debug-control",
    )
    add(
        action_id="web-cookie-target",
        candidate_id="web-cookie",
        candidate_type="insecure_session_cookie",
        purpose="candidate",
        risk_group="readonly",
        method="GET",
        path="/cookie",
    )
    add(
        action_id="web-cookie-control",
        candidate_id="web-cookie",
        candidate_type="insecure_session_cookie",
        purpose="negative_control",
        risk_group="readonly",
        method="GET",
        path="/cookie-control",
    )
    add(
        action_id="web-redirect-target",
        candidate_id="web-open-redirect",
        candidate_type="unvalidated_redirect",
        purpose="candidate",
        risk_group="readonly",
        method="GET",
        path="/redirect",
        query={"next": "https://redirect.invalid"},
        follow_redirects=False,
    )
    add(
        action_id="web-redirect-control",
        candidate_id="web-open-redirect",
        candidate_type="unvalidated_redirect",
        purpose="negative_control",
        risk_group="readonly",
        method="GET",
        path="/redirect-control",
        query={"next": "https://redirect.invalid"},
        follow_redirects=False,
    )
    add(
        action_id="authz-bola-owner-baseline",
        candidate_id="authz-bola",
        candidate_type="cross_tenant_object_read",
        purpose="baseline",
        risk_group="readonly",
        method="GET",
        path="/objects/1",
        identity_alias="bob",
    )
    add(
        action_id="authz-bola-cross-tenant",
        candidate_id="authz-bola",
        candidate_type="cross_tenant_object_read",
        purpose="candidate",
        risk_group="readonly",
        method="GET",
        path="/objects/2",
        identity_alias="alice",
    )
    add(
        action_id="authz-bola-control",
        candidate_id="authz-bola",
        candidate_type="cross_tenant_object_read",
        purpose="negative_control",
        risk_group="readonly",
        method="GET",
        path="/objects/2/control",
        identity_alias="alice",
    )

    # Mutation families with cleanup graphs.
    add(
        action_id="api-graphql-baseline",
        candidate_id="api-graphql",
        candidate_type="unauthorized_graphql_mutation",
        purpose="baseline",
        risk_group="mutation",
        method="GET",
        path="/graphql",
        identity_alias="alice",
    )
    add(
        action_id="api-graphql-forward",
        candidate_id="api-graphql",
        candidate_type="unauthorized_graphql_mutation",
        purpose="candidate",
        risk_group="mutation",
        method="POST",
        path="/graphql/mutate",
        body={"value": "phase5-mutated"},
        identity_alias="alice",
        depends_on=("api-graphql-baseline",),
    )
    add(
        action_id="api-graphql-control",
        candidate_id="api-graphql",
        candidate_type="unauthorized_graphql_mutation",
        purpose="negative_control",
        risk_group="mutation",
        method="POST",
        path="/graphql/control",
        body={"value": "phase5-control"},
        identity_alias="alice",
        depends_on=("api-graphql-baseline",),
    )
    add(
        action_id="api-graphql-cleanup",
        candidate_id="api-graphql",
        candidate_type="unauthorized_graphql_mutation",
        purpose="cleanup",
        risk_group="mutation",
        method="POST",
        path="/graphql/cleanup",
        body={"value": "initial"},
        identity_alias="fixture-admin",
        depends_on=("api-graphql-forward",),
        cleanup_of="api-graphql-forward",
    )
    add(
        action_id="api-graphql-cleanup-check",
        candidate_id="api-graphql",
        candidate_type="unauthorized_graphql_mutation",
        purpose="cleanup_check",
        risk_group="mutation",
        method="GET",
        path="/graphql",
        identity_alias="alice",
        depends_on=("api-graphql-cleanup",),
        cleanup_of="api-graphql-forward",
    )

    add(
        action_id="authz-privilege-baseline",
        candidate_id="authz-privilege",
        candidate_type="privilege_escalation",
        purpose="baseline",
        risk_group="mutation",
        method="GET",
        path="/authz/status",
        identity_alias="alice",
    )
    add(
        action_id="authz-privilege-forward",
        candidate_id="authz-privilege",
        candidate_type="privilege_escalation",
        purpose="candidate",
        risk_group="mutation",
        method="POST",
        path="/authz/elevate",
        body={"role": "admin"},
        identity_alias="alice",
        depends_on=("authz-privilege-baseline",),
    )
    add(
        action_id="authz-privilege-control",
        candidate_id="authz-privilege",
        candidate_type="privilege_escalation",
        purpose="negative_control",
        risk_group="mutation",
        method="GET",
        path="/authz/admin",
        identity_alias="fixture-admin",
        depends_on=("authz-privilege-baseline",),
    )
    add(
        action_id="authz-privilege-cleanup",
        candidate_id="authz-privilege",
        candidate_type="privilege_escalation",
        purpose="cleanup",
        risk_group="mutation",
        method="POST",
        path="/authz/revoke",
        body={"role": "viewer"},
        identity_alias="fixture-admin",
        depends_on=("authz-privilege-forward",),
        cleanup_of="authz-privilege-forward",
    )
    add(
        action_id="authz-privilege-cleanup-check",
        candidate_id="authz-privilege",
        candidate_type="privilege_escalation",
        purpose="cleanup_check",
        risk_group="mutation",
        method="GET",
        path="/authz/status",
        identity_alias="alice",
        depends_on=("authz-privilege-cleanup",),
        cleanup_of="authz-privilege-forward",
    )

    add(
        action_id="workflow-baseline",
        candidate_id="workflow-bypass",
        candidate_type="workflow_transition_bypass",
        purpose="baseline",
        risk_group="mutation",
        method="GET",
        path="/workflow/item/current",
        identity_alias="alice",
    )
    add(
        action_id="workflow-forward",
        candidate_id="workflow-bypass",
        candidate_type="workflow_transition_bypass",
        purpose="candidate",
        risk_group="mutation",
        method="POST",
        path="/workflow/direct-approve",
        body={"from": "draft", "to": "approved"},
        identity_alias="alice",
        depends_on=("workflow-baseline",),
    )
    add(
        action_id="workflow-control",
        candidate_id="workflow-bypass",
        candidate_type="workflow_transition_bypass",
        purpose="negative_control",
        risk_group="mutation",
        method="POST",
        path="/workflow/strict-approve",
        body={"from": "draft", "to": "approved"},
        identity_alias="alice",
        depends_on=("workflow-baseline",),
    )
    add(
        action_id="workflow-cleanup",
        candidate_id="workflow-bypass",
        candidate_type="workflow_transition_bypass",
        purpose="cleanup",
        risk_group="mutation",
        method="POST",
        path="/workflow/reset",
        body={"state": "draft"},
        identity_alias="fixture-admin",
        depends_on=("workflow-forward",),
        cleanup_of="workflow-forward",
    )
    add(
        action_id="workflow-cleanup-check",
        candidate_id="workflow-bypass",
        candidate_type="workflow_transition_bypass",
        purpose="cleanup_check",
        risk_group="mutation",
        method="GET",
        path="/workflow/item/current",
        identity_alias="alice",
        depends_on=("workflow-cleanup",),
        cleanup_of="workflow-forward",
    )

    return VerificationCampaignPlanV4(
        run_id=run_id,
        scope_digest=scope_digest,
        generated_by_task_id=generated_by_task_id,
        campaign_id=campaign_id,
        actions=tuple(actions),
        request_budget=len(actions),
        created_at=created_at,
        expires_at=expires_at,
    )


__all__ = [
    "ActionPurposeV4",
    "CampaignV4Error",
    "CandidateTypeV4",
    "RiskGroupV4",
    "VerificationActionV4",
    "VerificationCampaignPlanV4",
    "approval_actions_v4",
    "build_verification_campaign_v4",
    "campaign_candidate_ids",
]
