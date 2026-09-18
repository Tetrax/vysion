"""Legacy parity replay for canonical ALL services on Internet policies."""

from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    Applicability,
    AuditContext,
    AuditStatus,
    EvidenceCertainty,
    WanSelection,
    WanSelectionKind,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry


def _all_finding(raw: str, *, selected_wan: str):
    configuration = FortiGateParser().parse(raw)
    context = AuditContext(
        wan_selections=(
            WanSelection(name=selected_wan, kind=WanSelectionKind.INTERFACE),
        )
    )
    return next(
        finding
        for finding in AuditEngine(default_registry()).run(configuration, context=context)
        if finding.control_id == "FW-INTERNET-ALL-SERVICE-001"
    )


def _interfaces() -> str:
    return """config system interface
    edit "lan"
        set role lan
    next
    edit "uplink"
        set role undefined
    next
end
"""


def _policy(*, action: str, service: str) -> str:
    return f"""config firewall policy
    edit 10
        set status enable
        set srcintf "lan"
        set dstintf "uplink"
        set srcaddr "all"
        set dstaddr "all"
        set action {action}
        set schedule "always"
        set service "{service}"
    next
end
"""


def test_canonical_all_on_selected_wan_is_a_certain_failure() -> None:
    finding = _all_finding(
        _interfaces() + _policy(action="accept", service="ALL"),
        selected_wan="uplink",
    )

    assert finding.status is AuditStatus.FAIL
    assert [item.name for item in finding.affected_objects] == ["10"]
    assert finding.evidence_items
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_deny_policy_is_excluded_from_legacy_all_scope() -> None:
    finding = _all_finding(
        _interfaces() + _policy(action="deny", service="ALL"),
        selected_wan="uplink",
    )

    assert finding.status is AuditStatus.NOT_APPLICABLE


def test_unresolved_non_all_service_remains_unknown() -> None:
    finding = _all_finding(
        _interfaces() + _policy(action="accept", service="custom-web"),
        selected_wan="uplink",
    )

    assert finding.status is AuditStatus.UNKNOWN


def test_explicit_https_proves_no_all_without_optional_policy_defaults() -> None:
    raw = """config system interface
    edit "wan-lab"
        set role wan
    next
end
config firewall policy
    edit 1
        set srcintf "wan-lab"
        set dstintf "unresolved-destination"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
    next
end
"""

    finding = _all_finding(raw, selected_wan="wan-lab")

    assert finding.status is AuditStatus.PASS
    assert finding.applicability is Applicability.APPLICABLE
    assert any("HTTPS" in item.tokens for item in finding.evidence_items)
    assert finding.message == "Aucune règle n'autorise l'ensemble des services."
