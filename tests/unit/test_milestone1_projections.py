import pytest

from vysion.audit.models import ProofState
from vysion.audit.parser import FortiGateParser


def test_parser_builds_minimal_typed_relations_for_future_p0_controls() -> None:
    raw = """config system zone
    edit "internet"
        set interface "wan1" "wan2"
    next
end
config firewall policy
    edit 10
        set name "internet-egress"
        set srcintf "lan"
        set dstintf "internet"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end
config user local
    edit "breakglass"
        set type password
    next
end
config firewall ssl-ssh-profile
    edit "deep-inspection"
        set profile-type full
    next
end
"""

    configuration = FortiGateParser().parse(raw)

    assert configuration.zones[0].name == "internet"
    assert configuration.zones[0].interfaces[0].name == "wan1"
    assert configuration.zones[0].interfaces[0].object_type == "interface"
    assert configuration.policies[0].policy_id == "10"
    assert configuration.policies[0].source_interfaces[0].name == "lan"
    assert configuration.policies[0].destination_interfaces[0].name == "internet"
    assert configuration.policies[0].object_references[0].relation == "source-address"
    assert configuration.local_users[0].name == "breakglass"
    assert configuration.security_profiles[0].name == "deep-inspection"
    assert configuration.security_profiles[0].proof_state is ProofState.PROVEN


@pytest.mark.parametrize(
    ("section", "entry", "baseline", "mutation", "projection"),
    [
        (
            "system zone",
            '"internet"',
            'set interface "wan1"',
            'append interface "wan2"',
            "zones",
        ),
        (
            "firewall policy",
            "10",
            'set srcintf "lan"',
            'unset srcintf',
            "policies",
        ),
        (
            "user local",
            '"breakglass"',
            "set type password",
            "select type certificate",
            "local_users",
        ),
        (
            "firewall ssl-ssh-profile",
            '"inspection"',
            "set profile-type full",
            "unselect profile-type full",
            "security_profiles",
        ),
    ],
)
def test_generic_mutations_invalidate_the_projected_key(
    section: str,
    entry: str,
    baseline: str,
    mutation: str,
    projection: str,
) -> None:
    extra = (
        '\n        set dstintf "internet"\n'
        '        set srcaddr "all"\n'
        '        set dstaddr "all"\n'
        '        set action accept'
        if section == "firewall policy"
        else ""
    )
    raw = (
        f"config {section}\n"
        f"    edit {entry}\n"
        f"        {baseline}{extra}\n"
        f"        {mutation}\n"
        "    next\n"
        "end\n"
    )

    configuration = FortiGateParser().parse(raw)

    assert getattr(configuration, projection)[0].proof_state is ProofState.UNKNOWN


@pytest.mark.parametrize("duplicate_count", [2, 3])
def test_generic_duplicate_directives_never_become_proven_again(
    duplicate_count: int,
) -> None:
    directives = "\n".join(
        f'        set interface "wan{index}"' for index in range(1, duplicate_count + 1)
    )
    raw = f"""config system zone
    edit "internet"
{directives}
    next
end
"""

    configuration = FortiGateParser().parse(raw)

    assert configuration.zones[0].proof_state is ProofState.UNKNOWN


def test_repeated_disjoint_top_level_projected_sections_are_merged() -> None:
    raw = """config system interface
    edit "wan1"
    next
    edit "lan"
    next
end
config system zone
    edit "internet"
        set interface "wan1"
    next
end
config system zone
    edit "trusted"
        set interface "lan"
    next
end
"""

    configuration = FortiGateParser().parse(raw)

    assert {zone.name for zone in configuration.zones} == {"internet", "trusted"}
    assert all(zone.proof_state is ProofState.PROVEN for zone in configuration.zones)


def test_unknown_generic_directive_does_not_prove_a_projected_local_user() -> None:
    raw = """config user local
    edit "breakglass"
        set comment "operator note"
    next
end
"""

    local_user = FortiGateParser().parse(raw).local_users[0]

    assert local_user.proof_state is ProofState.UNKNOWN
    assert local_user.parsed_keys == frozenset()


def test_generic_projection_parsed_keys_exclude_uninterpreted_directives() -> None:
    raw = """config firewall policy
    edit 10
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set comment "operator note"
    next
end
"""

    policy = FortiGateParser().parse(raw).policies[0]

    assert policy.proof_state is ProofState.PROVEN
    assert "comment" not in policy.parsed_keys
    assert policy.parsed_keys == frozenset(
        {"srcintf", "dstintf", "srcaddr", "dstaddr", "action"}
    )


def test_empty_generic_projected_value_never_proves_the_projection() -> None:
    raw = """config system zone
    edit "internet"
        set interface
    next
end
"""

    configuration = FortiGateParser().parse(raw)
    zone = configuration.zones[0]
    entry = configuration.document.section("system zone").entries[0]

    assert zone.proof_state is ProofState.UNKNOWN
    assert zone.parsed_keys == frozenset()
    assert entry.certainty.value == "ambiguous"
    assert "interface" in entry.invalidated_keys
