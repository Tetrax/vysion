from __future__ import annotations

from collections.abc import Iterable

import pytest

from vysion.audit.engine import AuditEngine
from vysion.audit.models import Applicability, AuditPriority, AuditStatus
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

VPN_IDS = (
    "VPN-SSL-001",
    "VPN-IKEV2-001",
    "VPN-DH-001",
    "VPN-CRYPTO-001",
)


def audit(raw: str):
    configuration = FortiGateParser().parse(raw)
    return {
        finding.control_id: finding
        for finding in AuditEngine(default_registry()).run(configuration)
    }


def ssl_settings(*directives: str) -> str:
    return "config vpn ssl settings\n" + "".join(f"    {item}\n" for item in directives) + "end\n"


def phase1_entry(
    name: str = "p1",
    *,
    ike: str | None = "2",
    dh: str | None = "14",
    proposal: str | None = "aes256-sha256",
    interface: str | None = "wan1",
    extra: Iterable[str] = (),
) -> str:
    lines = [f'    edit "{name}"']
    if interface is not None:
        lines.append(f'        set interface "{interface}"')
    if ike is not None:
        lines.append(f"        set ike-version {ike}")
    if dh is not None:
        lines.append(f"        set dhgrp {dh}")
    if proposal is not None:
        lines.append(f"        set proposal {proposal}")
    lines.extend(f"        {item}" for item in extra)
    lines.extend(["    next"])
    return "\n".join(lines) + "\n"


def phase2_entry(
    name: str = "p2",
    *,
    phase1: str | None = "p1",
    dh: str | None = "14",
    proposal: str | None = "aes256-sha256",
    extra: Iterable[str] = (),
) -> str:
    lines = [f'    edit "{name}"']
    if phase1 is not None:
        lines.append(f'        set phase1name "{phase1}"')
    if dh is not None:
        lines.append(f"        set dhgrp {dh}")
    if proposal is not None:
        lines.append(f"        set proposal {proposal}")
    lines.extend(f"        {item}" for item in extra)
    lines.append("    next")
    return "\n".join(lines) + "\n"


def ipsec(*, phase1: str | None = "", phase2: str | None = "") -> str:
    result = ""
    if phase1 is not None:
        result += "config vpn ipsec phase1-interface\n" + phase1 + "end\n"
    if phase2 is not None:
        result += "config vpn ipsec phase2-interface\n" + phase2 + "end\n"
    return result


def strong() -> str:
    return ssl_settings("set status disable") + ipsec(
        phase1=phase1_entry(),
        phase2=phase2_entry(),
    )


def test_m4_registry_contains_exactly_four_vpn_p0_controls() -> None:
    controls = default_registry()
    findings = {
        finding.control_id: finding
        for finding in AuditEngine(controls).run(
            FortiGateParser().parse("config vpn ssl settings\n    set status disable\nend\n")
        )
    }

    vpn_findings = {
        control_id
        for control_id, finding in findings.items()
        if finding.category == "vpn" and finding.priority is AuditPriority.P0
    }
    assert vpn_findings == set(VPN_IDS)


def test_m4_registry_vpn_findings_have_p0_metadata() -> None:
    findings = {
        finding.control_id: finding
        for finding in AuditEngine(default_registry()).run(FortiGateParser().parse(strong()))
    }

    for control_id in VPN_IDS:
        assert findings[control_id].category == "vpn"
        assert findings[control_id].priority is AuditPriority.P0


def test_m4_strong_configuration_passes_all_vpn_controls() -> None:
    findings = audit(strong())

    assert [findings[control_id].status for control_id in VPN_IDS] == [
        AuditStatus.NOT_APPLICABLE,
        AuditStatus.PASS,
        AuditStatus.PASS,
        AuditStatus.PASS,
    ]
    assert findings["VPN-SSL-001"].applicability is Applicability.NOT_APPLICABLE
    assert all(
        item.certainty.value == "certain"
        for control_id in VPN_IDS
        for item in findings[control_id].evidence_items
    )


@pytest.mark.parametrize(
    "raw",
    [
        "config system global\nend\n",
        ssl_settings(),
        ssl_settings("set status auto"),
        ssl_settings("set status disable", "unset status"),
    ],
)
def test_m4_ssl_missing_incomplete_or_contradictory_is_unknown(raw: str) -> None:
    assert audit(raw)["VPN-SSL-001"].status is AuditStatus.UNKNOWN


@pytest.mark.parametrize(
    "directives",
    [
        ("set status enable",),
        ('set source-interface "wan1"',),
        ('set source-address "all"',),
        ('set default-portal "web-access"',),
    ],
)
def test_m4_ssl_explicit_usage_or_enable_fails(directives: tuple[str, ...]) -> None:
    assert audit(ssl_settings(*directives))["VPN-SSL-001"].status is AuditStatus.FAIL


def test_m4_ssl_disabled_with_retained_usage_is_unknown() -> None:
    raw = ssl_settings("set status disable", 'set source-interface "wan1"')

    finding = audit(raw)["VPN-SSL-001"]

    assert finding.status is AuditStatus.UNKNOWN
    assert finding.applicability is Applicability.UNKNOWN


@pytest.mark.parametrize("ike", ["1", "3", "0"])
def test_m4_explicit_non_v2_ike_fails(ike: str) -> None:
    raw = ssl_settings("set status disable") + ipsec(phase1=phase1_entry(ike=ike))

    assert audit(raw)["VPN-IKEV2-001"].status is AuditStatus.FAIL


def test_m4_ike_missing_or_non_integer_is_unknown() -> None:
    missing = ssl_settings("set status disable") + ipsec(phase1=phase1_entry(ike=None))
    non_integer = ssl_settings("set status disable") + ipsec(phase1=phase1_entry(ike="auto"))

    assert audit(missing)["VPN-IKEV2-001"].status is AuditStatus.UNKNOWN
    assert audit(non_integer)["VPN-IKEV2-001"].status is AuditStatus.UNKNOWN


def test_m4_ike_weak_explicit_version_dominates_missing_version() -> None:
    raw = ssl_settings("set status disable") + ipsec(
        phase1=phase1_entry("weak", ike="1") + phase1_entry("missing", ike=None),
    )

    assert audit(raw)["VPN-IKEV2-001"].status is AuditStatus.FAIL


def test_m4_dh_requires_all_phase1_and_phase2_groups() -> None:
    raw = ssl_settings("set status disable") + ipsec(
        phase1=phase1_entry(dh="14"),
        phase2=phase2_entry(dh="14"),
    )

    assert audit(raw)["VPN-DH-001"].status is AuditStatus.PASS


@pytest.mark.parametrize("dh", ["14", "19", "27"])
def test_m4_dh_accepts_supported_fortios_72_74_groups(dh: str) -> None:
    raw = ssl_settings("set status disable") + ipsec(
        phase1=phase1_entry(dh=dh),
        phase2=phase2_entry(dh=dh),
    )

    assert audit(raw)["VPN-DH-001"].status is AuditStatus.PASS


@pytest.mark.parametrize("dh", ["1", "5", "13"])
def test_m4_explicit_weak_dh_fails(dh: str) -> None:
    raw = ssl_settings("set status disable") + ipsec(phase1=phase1_entry(dh=dh))

    assert audit(raw)["VPN-DH-001"].status is AuditStatus.FAIL


def test_m4_dh_weak_phase2_fails() -> None:
    raw = ssl_settings("set status disable") + ipsec(phase2=phase2_entry(dh="5"))

    assert audit(raw)["VPN-DH-001"].status is AuditStatus.FAIL


@pytest.mark.parametrize(
    "phase1,phase2",
    [
        (phase1_entry(dh=None), phase2_entry()),
        (phase1_entry(), phase2_entry(dh=None)),
        (phase1_entry(), phase2_entry(phase1="missing")),
        (phase1_entry(dh="not-an-int"), phase2_entry()),
    ],
)
def test_m4_dh_missing_non_integer_or_orphan_is_unknown(phase1: str, phase2: str) -> None:
    raw = ssl_settings("set status disable") + ipsec(phase1=phase1, phase2=phase2)

    assert audit(raw)["VPN-DH-001"].status is AuditStatus.UNKNOWN


def test_m4_dh_both_explicitly_empty_is_not_applicable() -> None:
    raw = ssl_settings("set status disable") + ipsec(phase1="", phase2="")
    finding = audit(raw)["VPN-DH-001"]

    assert finding.status is AuditStatus.NOT_APPLICABLE
    assert finding.applicability is Applicability.NOT_APPLICABLE


def test_m4_all_explicitly_disabled_ipsec_phases_are_not_applicable_with_proof() -> None:
    raw = ssl_settings("set status disable") + ipsec(
        phase1=phase1_entry(
            dh="5",
            proposal="3des-md5",
            extra=("set status disable",),
        ),
        phase2=phase2_entry(
            dh="5",
            proposal="3des-md5",
            extra=("set status disable",),
        ),
    )
    findings = audit(raw)

    for control_id in ("VPN-IKEV2-001", "VPN-DH-001", "VPN-CRYPTO-001"):
        finding = findings[control_id]
        assert finding.status is AuditStatus.NOT_APPLICABLE
        assert finding.applicability is Applicability.NOT_APPLICABLE
        assert finding.evidence_items
        assert all(item.certainty.value == "certain" for item in finding.evidence_items)


def test_m4_dh_only_one_ipsec_section_is_unknown() -> None:
    raw = ssl_settings("set status disable") + ipsec(phase1="", phase2=None)

    assert audit(raw)["VPN-DH-001"].status is AuditStatus.UNKNOWN


@pytest.mark.parametrize(
    "proposal",
    [
        "3des-md5",
        "aes128-sha256",
        "unknown-token",
    ],
)
def test_m4_explicit_weak_or_unknown_crypto_fails(proposal: str) -> None:
    raw = ssl_settings("set status disable") + ipsec(
        phase1=phase1_entry(proposal=proposal),
        phase2=phase2_entry(),
    )

    assert audit(raw)["VPN-CRYPTO-001"].status is AuditStatus.FAIL


def test_m4_crypto_accepts_aead_and_non_aead_fortios_forms() -> None:
    raw = ssl_settings("set status disable") + ipsec(
        phase1=phase1_entry(proposal="aes256-sha256 aes256gcm-prfsha384"),
        phase2=phase2_entry(proposal="chacha20poly1305-prfsha512"),
    )

    assert audit(raw)["VPN-CRYPTO-001"].status is AuditStatus.PASS


def test_m4_crypto_missing_or_orphan_is_unknown() -> None:
    missing = ssl_settings("set status disable") + ipsec(
        phase1=phase1_entry(proposal=None),
        phase2=phase2_entry(),
    )
    orphan = ssl_settings("set status disable") + ipsec(
        phase1=phase1_entry(),
        phase2=phase2_entry(phase1="missing"),
    )

    assert audit(missing)["VPN-CRYPTO-001"].status is AuditStatus.UNKNOWN
    assert audit(orphan)["VPN-CRYPTO-001"].status is AuditStatus.UNKNOWN


def test_m4_crypto_ruleset_identity_is_visible_in_pass_evidence() -> None:
    finding = audit(strong())["VPN-CRYPTO-001"]

    assert "fortigate-vpn-crypto" in " ".join(finding.evidence)
    assert "2026-08-13" in finding.message


@pytest.mark.parametrize(
    "mutation",
    [
        "unset proposal",
        "append proposal aes256gcm",
        "select proposal aes256gcm",
        "unselect proposal aes256gcm",
    ],
)
def test_m4_crypto_mutations_are_unknown_not_pass(mutation: str) -> None:
    raw = ssl_settings("set status disable") + ipsec(
        phase1=phase1_entry(extra=(mutation,)),
        phase2=phase2_entry(),
    )

    assert audit(raw)["VPN-CRYPTO-001"].status is AuditStatus.UNKNOWN
