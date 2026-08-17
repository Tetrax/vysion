from datetime import date

import pytest
from pydantic import ValidationError

from vysion.audit.models import (
    AuditContext,
    AuditStatus,
    FortiGateConfiguration,
    ProofState,
    RuleMatchStatistics,
    UtmLicenseDetails,
    WanSelection,
    WanSelectionKind,
)
from vysion.audit.parser import FortiGateParser


def test_operator_context_contains_equipment_facts_and_structured_utm_license() -> None:
    context = AuditContext(
        client="Client métier",
        site="Paris-DC1",
        serial_number="FGT60E123456789",
        uptime="42 days, 03:12:10",
        operator_comment="HA à confirmer avec l’exploitant.",
        operator="Orange Business",
        ha=True,
        mpls=False,
        utm_license_details=UtmLicenseDetails(
            status="active",
            expiration_date=date(2027, 3, 31),
            provenance="FortiManager",
            manual=False,
        ),
    )

    assert context.utm_license is True
    assert context.utm_license_details is not None
    assert context.utm_license_details.status.value == "active"
    assert context.utm_license_details.expiration_date == date(2027, 3, 31)
    assert context.model_dump(mode="json")["utm_license_details"] == {
        "status": "active",
        "expiration_date": "2027-03-31",
        "provenance": "FortiManager",
        "manual": False,
    }
    assert context.operator == "Orange Business"
    assert context.operator_comment == "HA à confirmer avec l’exploitant."


def test_legacy_utm_boolean_is_kept_as_compatibility_projection() -> None:
    context = AuditContext(utm_license=False)

    assert context.utm_license is False
    assert context.utm_license_details is not None
    assert context.utm_license_details.status.value == "inactive"
    assert context.utm_license_details.manual is True


def test_utm_boolean_and_structured_status_cannot_contradict_each_other() -> None:
    with pytest.raises(ValidationError):
        AuditContext.model_validate(
            {
                "utm_license": True,
                "utm_license_details": {"status": "inactive"},
            }
        )


def test_utm_boolean_completes_missing_structured_status_consistently() -> None:
    context = AuditContext(
        utm_license=False,
        utm_license_details=UtmLicenseDetails(),
    )

    assert context.utm_license_details is not None
    assert context.utm_license_details.status is not None
    assert context.utm_license_details.status.value == "inactive"


@pytest.mark.parametrize(
    ("legacy_value", "expected"),
    [("true", True), ("1", True), ("false", False), ("0", False)],
)
def test_utm_legacy_text_values_are_coerced_before_structured_default(
    legacy_value: str,
    expected: bool,
) -> None:
    context = AuditContext.model_validate({"utm_license": legacy_value})

    assert context.utm_license is expected
    assert context.utm_license_details is not None
    assert context.utm_license_details.status.value == (
        "active" if expected else "inactive"
    )


def test_direct_automatic_wan_selection_is_canonicalized_without_warning() -> None:
    selection = WanSelection(name="automatic", kind=WanSelectionKind.AUTOMATIC)

    assert selection.automatic is True
    assert selection.model_dump()["automatic"] is True


def test_legacy_and_typed_wan_scopes_must_agree() -> None:
    with pytest.raises(ValidationError):
        AuditContext(
            selected_wans=("wan-risk",),
            wan_selections=(
                {"name": "wan-safe", "kind": WanSelectionKind.INTERFACE},
            ),
        )


def test_zone_selection_keeps_typed_interface_relation_from_structural_parser() -> None:
    configuration = FortiGateParser().parse(
        """config system global
    set hostname zone-lab
end
config system interface
    edit "wan1"
        set role wan
        set allowaccess ping
    next
    edit "lan1"
        set role lan
        set allowaccess ping
    next
end
config system zone
    edit "internet"
        set interface "wan1"
    next
end
config system sdwan
    edit "virtual-wan-link"
        set interface "wan1"
    next
end
"""
    )

    assert configuration.interfaces[0].zone is not None
    assert configuration.interfaces[0].zone.name == "internet"
    assert configuration.interfaces[0].zone.object_type == "zone"
    assert configuration.interfaces[0].zone.relation == "member-of"
    assert configuration.zones[0].proof_state is ProofState.PROVEN
    assert configuration.sdwan_zones[0].name == "virtual-wan-link"
    assert configuration.sdwan_zones[0].interfaces[0].name == "wan1"


def test_wan_selection_model_distinguishes_interface_zone_and_automatic_scope() -> None:
    context = AuditContext(
        wan_selections=(
            {"name": "wan1", "kind": WanSelectionKind.INTERFACE},
            {"name": "internet", "kind": WanSelectionKind.ZONE, "interfaces": ("wan1",)},
            {"name": "automatic", "kind": WanSelectionKind.AUTOMATIC, "automatic": True},
        )
    )

    assert [selection.kind for selection in context.wan_selections or ()] == [
        WanSelectionKind.INTERFACE,
        WanSelectionKind.ZONE,
        WanSelectionKind.AUTOMATIC,
    ]
    assert context.selected_wans == ("wan1", "internet", "automatic")


def test_status_vocabulary_remains_fail_closed_and_unchanged() -> None:
    assert set(status.value for status in AuditStatus) == {
        "PASS",
        "FAIL",
        "UNKNOWN",
        "NOT_APPLICABLE",
        "ERROR",
    }


def test_rule_match_statistics_are_optional_operator_observations_not_a_control_proof() -> None:
    context = AuditContext(
        rule_match_statistics=RuleMatchStatistics(
            unmatched_rules=7,
            source="operator",
            method="Firewall policy Hit Count <= 0",
        )
    )

    payload = context.model_dump(mode="json")

    assert payload["rule_match_statistics"] == {
        "unmatched_rules": 7,
        "total_rules": None,
        "source": "operator",
        "method": "Firewall policy Hit Count <= 0",
    }
    assert context.ha is None
    assert FortiGateConfiguration().complete_backup is False
