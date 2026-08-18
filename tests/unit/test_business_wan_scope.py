from vysion.api.app import _preview_payload, _selected_wan_scopes
from vysion.audit.controls.external_services import _wan_names
from vysion.audit.controls.network import check_wan_management_access
from vysion.audit.models import (
    AuditContext,
    AuditStatus,
    FortiGateConfiguration,
    Interface,
    ObjectReference,
    ProofState,
    WanSelection,
    WanSelectionKind,
    Zone,
)
from vysion.audit.parser import FortiGateParser


def test_wan_management_uses_the_resolved_interface_of_a_selected_zone() -> None:
    configuration = FortiGateParser().parse(
        """config system interface
    edit "wan1"
        set role wan
        set allowaccess https
    next
end
config system zone
    edit "internet"
        set interface "wan1"
    next
end
"""
    )
    context = AuditContext(
        wan_selections=(
            {
                "name": "internet",
                "kind": WanSelectionKind.ZONE,
                "interfaces": ("wan1",),
            },
        )
    )

    finding = check_wan_management_access(configuration, context)

    assert finding.status.value == "FAIL"
    assert "wan1" in {item.name for item in finding.affected_objects}


def test_casefold_zone_collision_is_unknown_and_not_resolved_to_last_entry() -> None:
    configuration = FortiGateParser().parse(
        """config system interface
    edit "wan1"
        set role wan
        set allowaccess https
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
    edit "INTERNET"
        set interface "lan1"
    next
end
"""
    )

    assert all(zone.proof_state.value == "unknown" for zone in configuration.zones)
    selections = _selected_wan_scopes(
        ['[{"name":"internet","kind":"zone"}]'], configuration
    )

    assert selections is not None
    assert selections[0].interfaces == ()

    assert _preview_payload(configuration)["zones"] == []

    invalid_preview_configuration = configuration.model_copy(
        update={
            "zones": tuple(
                zone.model_copy(
                    update={
                        "proof_state": ProofState.PROVEN,
                        "interfaces": (
                            ObjectReference(
                                object_type="interface",
                                name="missing",
                                relation="zone-interface",
                            ),
                        ),
                    }
                )
                for zone in (configuration.zones[0],)
            )
        }
    )
    assert _preview_payload(invalid_preview_configuration)["zones"] == []

    proven_configuration = configuration.model_copy(
        update={
            "zones": tuple(
                zone.model_copy(
                    update={
                        "proof_state": ProofState.PROVEN,
                        "interfaces": (
                            ObjectReference(
                                object_type="interface",
                                name="wan1" if zone.name == "internet" else "lan1",
                                relation="zone-interface",
                            ),
                        ),
                    }
                )
                for zone in configuration.zones
            )
        }
    )
    context = AuditContext(
        wan_selections=(WanSelection(name="internet", kind=WanSelectionKind.ZONE),)
    )

    finding = check_wan_management_access(proven_configuration, context)
    assert finding.status.value == "UNKNOWN"
    _, proven = _wan_names(proven_configuration, context)
    assert proven is False


def test_standard_nested_sdwan_zone_members_are_projected() -> None:
    configuration = FortiGateParser().parse(
        """config system interface
    edit "wan1"
        set role wan
        set allowaccess https
    next
end
config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
    end
    config members
        edit 1
            set interface wan1
        next
    end
end
"""
    )

    assert [
        (zone.name, tuple(reference.name for reference in zone.interfaces))
        for zone in configuration.sdwan_zones
    ] == [("virtual-wan-link", ("wan1",))]
    assert configuration.sdwan_zones[0].interfaces[0].relation == "sdwan-member"
    assert configuration.sdwan_zones[0].proof_state.value == "proven"


def test_sdwan_zone_survives_non_membership_options_and_child_blocks() -> None:
    configuration = FortiGateParser().parse(
        """config system interface
    edit "wan1"
        set role wan
        set allowaccess ping
    next
    edit "wan2"
        set role wan
        set allowaccess ping
    next
end
config system sdwan
    set status enable
    set load-balance-mode source-ip-based
    set release-specific-option enable
    config zone
        edit "Z-INTERSITE"
        next
    end
    config members
        edit 1
            set interface "wan1"
            set gateway 192.0.2.1
        next
        edit 2
            set interface "wan2"
        next
    end
    config health-check
        edit "inter-site"
            set server "192.0.2.1"
            set members 1 2
            set update-static-route disable
        next
    end
    config service
        edit 1
            set name "inter-site"
            set mode sla
            set dst "all"
            set src "all"
            set health-check "inter-site"
            set priority-members 1 2
            set priority-zone "Z-INTERSITE"
        next
    end
end
"""
    )

    sdwan = configuration.sdwan_zones[0]

    sdwan_section = configuration.document.section("system sdwan")
    assert sdwan_section is not None
    assert sdwan_section.certainty.value == "certain"
    assert sdwan.name == "Z-INTERSITE"
    assert [reference.name for reference in sdwan.interfaces] == ["wan1", "wan2"]
    assert sdwan.proof_state.value == "proven"


def test_nested_sdwan_zone_with_unknown_child_is_unknown() -> None:
    configuration = FortiGateParser().parse(
        """config system interface
    edit "wan-safe"
        set role wan
        set allowaccess ping
    next
    edit "wan-risk"
        set role wan
        set allowaccess https
    next
end
config system sdwan
    config zone
        edit "virtual-wan-link"
            set interface "wan-safe"
            config bogus
                set interface "wan-risk"
            end
        next
    end
end
"""
    )

    zone = configuration.sdwan_zones[0]
    assert zone.proof_state is ProofState.UNKNOWN
    finding = check_wan_management_access(
        configuration,
        AuditContext(
            wan_selections=(
                WanSelection(name="virtual-wan-link", kind=WanSelectionKind.SDWAN),
            )
        ),
    )
    assert finding.status is AuditStatus.UNKNOWN
    assert _preview_payload(configuration)["sdwan_zones"] == []


def test_flat_sdwan_entry_with_interface_and_member_aliases_is_unknown() -> None:
    configuration = FortiGateParser().parse(
        """config system interface
    edit "wan-safe"
        set role wan
        set allowaccess ping
    next
    edit "wan-risk"
        set role wan
        set allowaccess https
    next
end
config system sdwan
    edit "virtual-wan-link"
        set interface "wan-safe"
        set member "wan-risk"
    next
end
"""
    )

    zone = configuration.sdwan_zones[0]
    assert zone.proof_state.value == "unknown"
    finding = check_wan_management_access(
        configuration,
        AuditContext(
            wan_selections=(
                WanSelection(name="virtual-wan-link", kind=WanSelectionKind.SDWAN),
            )
        ),
    )
    assert finding.status.value == "UNKNOWN"


def test_nested_sdwan_zone_with_interface_and_member_aliases_is_unknown() -> None:
    configuration = FortiGateParser().parse(
        """config system interface
    edit "wan-safe"
        set role wan
        set allowaccess ping
    next
    edit "wan-risk"
        set role wan
        set allowaccess https
    next
end
config system sdwan
    config zone
        edit "virtual-wan-link"
            set interface "wan-safe"
            set member "wan-risk"
        next
    end
end
"""
    )

    zone = configuration.sdwan_zones[0]
    assert zone.proof_state.value == "unknown"
    finding = check_wan_management_access(
        configuration,
        AuditContext(
            wan_selections=(
                WanSelection(name="virtual-wan-link", kind=WanSelectionKind.SDWAN),
            )
        ),
    )
    assert finding.status.value == "UNKNOWN"


def test_zone_with_missing_interface_reference_is_not_proven() -> None:
    configuration = FortiGateParser().parse(
        """config system zone
    edit "internet"
        set interface "missing"
    next
end
"""
    )

    zone = configuration.zones[0]
    assert zone.interfaces[0].name == "missing"
    assert zone.proof_state.value == "unknown"


def test_api_rejects_even_manually_constructed_proven_zone_with_missing_interface() -> None:
    configuration = FortiGateConfiguration(
        interfaces=(Interface(name="wan1"),),
        zones=(
            Zone(
                name="internet",
                interfaces=(
                    ObjectReference(object_type="interface", name="missing"),
                ),
                proof_state=ProofState.PROVEN,
            ),
        ),
    )

    selections = _selected_wan_scopes(
        ['[{"name":"internet","kind":"zone"}]'], configuration
    )

    assert selections is not None
    assert selections[0].interfaces == ()
