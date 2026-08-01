from __future__ import annotations

from datetime import UTC, datetime, timedelta

from hermes.campaign_v4 import (
    approval_actions_v4,
    build_verification_campaign_v4,
    campaign_candidate_ids,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def campaign():
    now = datetime(2026, 7, 29, 12, tzinfo=UTC)
    return build_verification_campaign_v4(
        run_id="run-v4",
        scope_digest=digest("a"),
        generated_by_task_id="campaign-v4",
        endpoint_base="https://localhost:8443",
        identity_binding_digests={
            "alice": digest("1"),
            "bob": digest("2"),
            "fixture-admin": digest("3"),
        },
        created_at=now,
        expires_at=now + timedelta(minutes=15),
    )


def test_fixed_campaign_has_eight_candidates_and_exact_request_budgets() -> None:
    value = campaign()

    assert value.discovery_request_budget == 2
    assert value.request_budget == 26
    assert value.total_request_budget == 28
    assert campaign_candidate_ids(value) == (
        "web-xcto",
        "infra-debug",
        "api-graphql",
        "authz-privilege",
        "web-cookie",
        "authz-bola",
        "web-open-redirect",
        "workflow-bypass",
    )


def test_risk_groups_and_cleanup_graph_match_phase5_contract() -> None:
    value = campaign()

    readonly = approval_actions_v4(value, "readonly")
    mutation = approval_actions_v4(value, "mutation")
    cleanup = approval_actions_v4(value, "cleanup")

    assert len(readonly) == 11
    assert len(mutation) == 15
    assert len(cleanup) == 6
    assert {item.candidate_id for item in cleanup} == {
        "api-graphql",
        "authz-privilege",
        "workflow-bypass",
    }
    assert {item.purpose for item in cleanup} == {"cleanup", "cleanup_check"}


def test_redirect_candidate_binds_no_follow_transport_metadata() -> None:
    value = campaign()

    redirect = tuple(item for item in value.actions if item.candidate_id == "web-open-redirect")
    assert len(redirect) == 2
    assert all(item.method == "GET" for item in redirect)
    assert all(item.follow_redirects is False for item in redirect)


def test_graphql_baseline_is_a_non_mutating_get_matching_the_local_fixture() -> None:
    value = campaign()
    baseline = next(item for item in value.actions if item.action_id == "api-graphql-baseline")

    assert baseline.method == "GET"
    assert baseline.action_kind == "validation_http_get"


def test_campaign_routes_are_rooted_at_origin_when_target_is_a_concrete_entrypoint() -> None:
    now = datetime(2026, 7, 29, 12, tzinfo=UTC)
    value = build_verification_campaign_v4(
        run_id="run-v4",
        scope_digest=digest("a"),
        generated_by_task_id="campaign-v4",
        endpoint_base="https://localhost:8443/candidate",
        identity_binding_digests={
            "alice": digest("1"),
            "bob": digest("2"),
            "fixture-admin": digest("3"),
        },
        created_at=now,
        expires_at=now + timedelta(minutes=15),
    )

    targets = {item.action_id: item.target_url for item in value.actions}
    assert targets["web-xcto-target"] == "https://localhost:8443/candidate"
    assert targets["api-graphql-baseline"] == "https://localhost:8443/graphql"
    assert targets["workflow-cleanup-check"] == "https://localhost:8443/workflow/item/current"
    assert all("/candidate/" not in target for target in targets.values())


def test_branch_isolated_campaign_contains_only_selected_action_subgraphs() -> None:
    now = datetime(2026, 7, 29, 12, tzinfo=UTC)
    value = build_verification_campaign_v4(
        run_id="run-v4",
        scope_digest=digest("a"),
        generated_by_task_id="campaign-v4",
        endpoint_base="https://localhost:8443/candidate",
        identity_binding_digests={
            "alice": digest("1"),
            "bob": digest("2"),
            "fixture-admin": digest("3"),
        },
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        candidate_types=("missing_x_content_type_options", "exposed_debug_endpoint"),
    )

    assert campaign_candidate_ids(value) == ("web-xcto", "infra-debug")
    assert value.request_budget == 4
    assert value.total_request_budget == 6
    assert {item.risk_group for item in value.actions} == {"readonly"}
