from __future__ import annotations

import pytest

from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    Applicability,
    AuditContext,
    AuditPriority,
    AuditStatus,
    EvidenceCertainty,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry


def audit(raw: str, context: AuditContext | None = None):
    configuration = FortiGateParser().parse(raw)
    return {
        finding.control_id: finding
        for finding in AuditEngine(default_registry()).run(configuration, context=context)
    }


def evidence_text(finding) -> str:
    return " ".join(str(item) for item in finding.evidence)


def interface_block(
    *, allowaccess: str | None = "ping", role: str | None = "wan", nested: str = ""
) -> str:
    role_line = f"        set role {role}\n" if role is not None else ""
    allow_line = f"        set allowaccess {allowaccess}\n" if allowaccess is not None else ""
    return f"""config system interface
    edit "wan1"
{role_line}{allow_line}{nested}    next
end
"""


def admin_block(*entries: str) -> str:
    return "config system admin\n" + "".join(entries) + "end\n"


def admin_entry(name: str, directives: str) -> str:
    return f'''    edit "{name}"
{directives}    next
'''


def local_block(*entries: str) -> str:
    return "config user local\n" + "".join(entries) + "end\n"


def local_entry(name: str, directives: str) -> str:
    return f'''    edit "{name}"
{directives}    next
'''


M2_IDS = {
    "NET-WAN-MGMT-001",
    "IAM-ADMIN-MFA-001",
    "IAM-LOCAL-USER-MFA-001",
    "IAM-DEFAULT-ADMIN-001",
    "IAM-GUEST-ACCOUNT-001",
}


def test_m2_controls_are_independent_p0_findings_with_enriched_metadata() -> None:
    findings = audit(
        interface_block()
        + admin_block(admin_entry("secops", "        set two-factor fortitoken\n"))
        + local_block(
            local_entry("vpn", "        set type password\n        set two-factor email\n")
        )
    )

    assert findings.keys() >= M2_IDS
    for control_id in M2_IDS:
        finding = findings[control_id]
        assert finding.priority is AuditPriority.P0
        assert finding.risk is not None
        assert finding.remediation
        assert finding.evidence_items


def test_wan_pass_requires_explicit_safe_allowaccess_on_primary_and_secondary_points() -> None:
    nested = """        config secondaryip
            edit 1
                set ip 198.51.100.2 255.255.255.255
                set allowaccess ping
            next
        end
"""

    finding = audit(interface_block(nested=nested))["NET-WAN-MGMT-001"]

    assert finding.status is AuditStatus.PASS
    assert {item.name for item in finding.affected_objects} >= {
        "wan1",
        "wan1.secondaryip[1]",
    }


@pytest.mark.parametrize("protocol", ["ssh", "http", "https"])
def test_wan_fails_for_each_forbidden_protocol(protocol: str) -> None:
    finding = audit(interface_block(allowaccess=f"ping {protocol}"))["NET-WAN-MGMT-001"]

    assert finding.status is AuditStatus.FAIL
    assert protocol in evidence_text(finding).lower()
    assert finding.affected_objects[0].name == "wan1"


def test_wan_fails_when_secondary_access_point_exposes_https() -> None:
    nested = """        config secondaryip
            edit 1
                set ip 198.51.100.2 255.255.255.255
                set allowaccess ping https
            next
        end
"""

    finding = audit(interface_block(nested=nested))["NET-WAN-MGMT-001"]

    assert finding.status is AuditStatus.FAIL
    assert "wan1.secondaryip[1]" in {item.name for item in finding.affected_objects}


def test_wan_unknown_secondary_allowaccess_value_is_not_proof_of_safety() -> None:
    nested = """        config secondaryip
            edit 1
                set ip 198.51.100.2 255.255.255.255
                set allowaccess ping future-protocol
            next
        end
"""

    finding = audit(interface_block(nested=nested))["NET-WAN-MGMT-001"]

    assert finding.status is AuditStatus.UNKNOWN
    assert "secondaryip[1]" in evidence_text(finding)


def test_wan_explicit_forbidden_token_dominates_unknown_token() -> None:
    finding = audit(interface_block(allowaccess="ping https future-protocol"))[
        "NET-WAN-MGMT-001"
    ]

    assert finding.status is AuditStatus.FAIL
    assert "https" in evidence_text(finding).lower()


def test_wan_without_structural_role_is_unknown_when_context_is_omitted() -> None:
    finding = audit(interface_block(role=None))["NET-WAN-MGMT-001"]

    assert finding.status is AuditStatus.UNKNOWN


def test_explicit_wan_selection_is_authoritative_for_any_certain_typed_interface() -> None:
    raw = """config system interface
    edit "wan1"
        set role wan
        set allowaccess ping
    next
    edit "port1"
        set role lan
        set allowaccess ping
    next
end
"""

    finding = audit(raw, AuditContext(selected_wans=("port1",)))["NET-WAN-MGMT-001"]

    assert finding.status is AuditStatus.PASS
    assert finding.affected_objects[0].name == "port1"


def test_unknown_wan_selection_is_unknown_even_when_another_interface_is_safe() -> None:
    finding = audit(
        interface_block(),
        AuditContext(selected_wans=("wan1", "missing")),
    )["NET-WAN-MGMT-001"]

    assert finding.status is AuditStatus.UNKNOWN
    assert "missing" in evidence_text(finding)


def test_certain_wan_violation_dominates_unknown_selected_wan_name() -> None:
    finding = audit(
        interface_block(allowaccess="ping ssh"),
        AuditContext(selected_wans=("wan1", "missing")),
    )["NET-WAN-MGMT-001"]

    assert finding.status is AuditStatus.FAIL
    assert "wan1" in evidence_text(finding)
    assert "missing" in evidence_text(finding)


def test_wan_missing_secondary_allowaccess_is_unknown() -> None:
    nested = """        config secondaryip
            edit 1
                set ip 198.51.100.2 255.255.255.255
            next
        end
"""

    finding = audit(interface_block(nested=nested))["NET-WAN-MGMT-001"]

    assert finding.status is AuditStatus.UNKNOWN
    assert "secondaryip[1]" in " ".join(finding.evidence)


def test_wan_unknown_secondary_allowaccess_is_unknown() -> None:
    nested = """        config secondaryip
            edit 1
                set ip 198.51.100.2 255.255.255.255
                set allowaccess ping future-management
            next
        end
"""

    finding = audit(interface_block(nested=nested))["NET-WAN-MGMT-001"]

    assert finding.status is AuditStatus.UNKNOWN


def test_wan_conflicting_nested_allowaccess_is_unknown_without_a_certain_violation() -> None:
    nested = """        config secondaryip
            edit 1
                set ip 198.51.100.2 255.255.255.255
                set allowaccess ping
                set allowaccess ping
            next
        end
"""

    finding = audit(interface_block(nested=nested))["NET-WAN-MGMT-001"]

    assert finding.status is AuditStatus.UNKNOWN


def test_wan_explicit_violation_dominates_another_unknown_access_point() -> None:
    nested = """        config secondaryip
            edit 1
                set ip 198.51.100.2 255.255.255.255
                set allowaccess https
            next
            edit 2
                set ip 198.51.100.3 255.255.255.255
            next
        end
"""

    finding = audit(interface_block(nested=nested))["NET-WAN-MGMT-001"]

    assert finding.status is AuditStatus.FAIL


@pytest.mark.parametrize("method", ["fortitoken", "email", "sms"])
def test_admin_supported_mfa_is_pass(method: str) -> None:
    finding = audit(admin_block(admin_entry("admin-one", f"        set two-factor {method}\n")))[
        "IAM-ADMIN-MFA-001"
    ]

    assert finding.status is AuditStatus.PASS
    assert finding.applicability is Applicability.APPLICABLE


@pytest.mark.parametrize("method", ["none", "disable", '""'])
def test_admin_explicitly_disabled_or_empty_mfa_is_fail(method: str) -> None:
    finding = audit(admin_block(admin_entry("admin-one", f"        set two-factor {method}\n")))[
        "IAM-ADMIN-MFA-001"
    ]

    assert finding.status is AuditStatus.FAIL


def test_admin_missing_mfa_is_unknown() -> None:
    finding = audit(admin_block(admin_entry("admin-one", "        set accprofile super_admin\n")))[
        "IAM-ADMIN-MFA-001"
    ]

    assert finding.status is AuditStatus.UNKNOWN


def test_nested_admin_namespace_cannot_prove_account_absence() -> None:
    raw = """config system admin
    config hidden
        edit "admin"
            set two-factor none
        next
    end
end
config user local
end
"""
    findings = audit(raw)

    assert findings["IAM-DEFAULT-ADMIN-001"].status is AuditStatus.UNKNOWN
    assert findings["IAM-GUEST-ACCOUNT-001"].status is AuditStatus.PASS


def test_admin_explicit_failure_dominates_unknown_admin() -> None:
    finding = audit(
        admin_block(
            admin_entry("unsafe", "        set two-factor none\n"),
            admin_entry("uncertain", "        set accprofile super_admin\n"),
        )
    )["IAM-ADMIN-MFA-001"]

    assert finding.status is AuditStatus.FAIL
    assert "unsafe" in evidence_text(finding)


def test_admin_certain_peer_auth_is_not_applicable() -> None:
    finding = audit(
        admin_block(
            admin_entry(
                "peer-admin",
                "        set peer-auth enable\n        set accprofile super_admin\n",
            )
        )
    )["IAM-ADMIN-MFA-001"]

    assert finding.status is AuditStatus.NOT_APPLICABLE
    assert finding.applicability is Applicability.NOT_APPLICABLE


def test_ambiguous_peer_auth_does_not_bypass_missing_admin_mfa() -> None:
    finding = audit(
        admin_block(
            admin_entry(
                "peer-admin",
                "        set peer-auth enable\n        unset peer-auth\n",
            )
        )
    )["IAM-ADMIN-MFA-001"]

    assert finding.status is AuditStatus.UNKNOWN
    assert finding.applicability is Applicability.UNKNOWN


@pytest.mark.parametrize("mutation", ["unset", "append", "select", "unselect"])
def test_admin_mfa_mutation_invalidates_an_explicit_disabled_value(mutation: str) -> None:
    finding = audit(
        admin_block(
            admin_entry(
                "admin-one",
                f"        set two-factor none\n        {mutation} two-factor fortitoken\n",
            )
        )
    )["IAM-ADMIN-MFA-001"]

    assert finding.status is AuditStatus.UNKNOWN


def test_directive_outside_local_user_entry_cannot_prove_empty_namespace() -> None:
    finding = audit(local_block("    set two-factor none\n"))[
        "IAM-LOCAL-USER-MFA-001"
    ]

    assert finding.status is AuditStatus.UNKNOWN


def test_nested_local_user_namespace_cannot_prove_mfa_or_guest_absence() -> None:
    raw = """config system admin
end
config user local
    config hidden
        edit "guest"
            set type password
            set two-factor none
        next
    end
end
"""
    findings = audit(raw)

    assert findings["IAM-LOCAL-USER-MFA-001"].status is AuditStatus.UNKNOWN
    assert findings["IAM-GUEST-ACCOUNT-001"].status is AuditStatus.UNKNOWN


def test_local_user_supported_mfa_is_pass() -> None:
    finding = audit(
        local_block(local_entry("vpn", "        set type password\n        set two-factor sms\n"))
    )["IAM-LOCAL-USER-MFA-001"]

    assert finding.status is AuditStatus.PASS


@pytest.mark.parametrize("method", ["none", "disable", '""'])
def test_local_user_disabled_or_empty_mfa_is_fail(method: str) -> None:
    finding = audit(
        local_block(
            local_entry("vpn", f"        set type password\n        set two-factor {method}\n")
        )
    )["IAM-LOCAL-USER-MFA-001"]

    assert finding.status is AuditStatus.FAIL


def test_local_user_missing_mfa_is_unknown_and_peer_auth_is_not_an_exception() -> None:
    finding = audit(
        local_block(
            local_entry(
                "vpn",
                "        set type password\n        set peer-auth enable\n",
            )
        )
    )["IAM-LOCAL-USER-MFA-001"]

    assert finding.status is AuditStatus.UNKNOWN


@pytest.mark.parametrize("mutation", ["unset", "append", "select", "unselect"])
def test_local_user_mfa_mutation_invalidates_explicit_disabled_value(mutation: str) -> None:
    finding = audit(
        local_block(
            local_entry(
                "vpn",
                f"        set two-factor none\n        {mutation} two-factor fortitoken\n",
            )
        )
    )["IAM-LOCAL-USER-MFA-001"]

    assert finding.status is AuditStatus.UNKNOWN


def test_empty_certain_local_user_section_is_not_applicable() -> None:
    finding = audit("config user local\nend\n")["IAM-LOCAL-USER-MFA-001"]

    assert finding.status is AuditStatus.NOT_APPLICABLE
    assert finding.applicability is Applicability.NOT_APPLICABLE


def test_default_admin_absence_passes_only_with_complete_admin_namespace() -> None:
    findings = audit(admin_block(admin_entry("secops", "        set two-factor fortitoken\n")))

    finding = findings["IAM-DEFAULT-ADMIN-001"]
    assert finding.status is AuditStatus.PASS
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)
    assert finding.evidence_items[0].directive is None
    assert finding.evidence_items[0].tokens == ("secops",)


@pytest.mark.parametrize("name", ["admin", "ADMIN", "AdMiN"])
def test_default_admin_case_insensitive_presence_fails(name: str) -> None:
    finding = audit(admin_block(admin_entry(name, "        set two-factor fortitoken\n")))[
        "IAM-DEFAULT-ADMIN-001"
    ]

    assert finding.status is AuditStatus.FAIL


def test_default_admin_missing_namespace_is_unknown() -> None:
    finding = audit("config system global\n    set hostname edge.example\nend\n")[
        "IAM-DEFAULT-ADMIN-001"
    ]

    assert finding.status is AuditStatus.UNKNOWN


def test_default_admin_presence_dominates_entry_ambiguity() -> None:
    finding = audit(
        admin_block(
            admin_entry(
                "admin",
                "        set accprofile super_admin\n        unset accprofile\n",
            )
        )
    )["IAM-DEFAULT-ADMIN-001"]

    assert finding.status is AuditStatus.FAIL


def test_guest_absence_requires_complete_user_local_namespace() -> None:
    findings = audit(
        admin_block(admin_entry("secops", "        set two-factor fortitoken\n"))
        + "config user local\nend\n"
    )

    finding = findings["IAM-GUEST-ACCOUNT-001"]
    assert finding.status is AuditStatus.PASS
    assert len(finding.evidence_items) == 1
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)
    assert all(item.directive is None for item in finding.evidence_items)


def test_guest_only_in_user_local_namespace_fails_case_insensitively() -> None:
    admin_finding = audit(
        admin_block(admin_entry("Guest", "        set two-factor fortitoken\n"))
        + "config user local\nend\n"
    )["IAM-GUEST-ACCOUNT-001"]
    local_finding = audit(
        admin_block(admin_entry("secops", "        set two-factor fortitoken\n"))
        + local_block(
            local_entry("GUEST", "        set type password\n        set two-factor sms\n")
        )
    )["IAM-GUEST-ACCOUNT-001"]

    assert admin_finding.status is AuditStatus.PASS
    assert local_finding.status is AuditStatus.FAIL


def test_guest_unknown_when_one_namespace_is_absent_and_no_guest_is_found() -> None:
    finding = audit(admin_block(admin_entry("secops", "        set two-factor fortitoken\n")))[
        "IAM-GUEST-ACCOUNT-001"
    ]

    assert finding.status is AuditStatus.UNKNOWN


def test_guest_unknown_when_local_namespace_is_conflicted() -> None:
    raw = (
        admin_block(admin_entry("secops", "        set two-factor fortitoken\n"))
        + """config user local
    edit "vpn"
        set type password
        set type password
    next
end
"""
    )

    finding = audit(raw)["IAM-GUEST-ACCOUNT-001"]

    assert finding.status is AuditStatus.UNKNOWN


def test_realistic_fixture_exposes_all_m2_controls_as_pass() -> None:
    from pathlib import Path

    fixture = Path(__file__).parents[1] / "fixtures" / "anonymized_fortigate_export.conf"
    findings = audit(fixture.read_text(encoding="utf-8"))

    assert [findings[control_id].status for control_id in sorted(M2_IDS)] == [
        AuditStatus.PASS,
        AuditStatus.PASS,
        AuditStatus.PASS,
        AuditStatus.PASS,
        AuditStatus.PASS,
    ]
