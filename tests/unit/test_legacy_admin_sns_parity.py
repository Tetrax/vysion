from __future__ import annotations

import pytest

from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    AuditContext,
    AuditStatus,
    ContextProvenance,
    LegacyV1AdminPolicy,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

CONTROL_IDS = (
    "IAM-LEGACY-ADMIN-001",
    "IAM-LEGACY-PKI-REMOVAL-001",
    "IAM-LEGACY-PKI-PRESENCE-001",
    "NET-LEGACY-ADMIN-LOOPBACK-001",
    "DNS-LEGACY-DATABASE-001",
)


def _context() -> AuditContext:
    return AuditContext(
        operator_provenance=ContextProvenance(source="operator-policy"),
        legacy_v1_admin_policy=LegacyV1AdminPolicy(
            local_admin_names=("vendor-admin", "support-admin"),
            local_admin_mfa_email="support@example.invalid",
            pki_peer_group="vendor-pki-group",
            deprecated_pki_account="legacy-pki",
            required_pki_account="managed-pki",
            administration_fqdn="admin.example.invalid",
            dns_database_entry="admin.example.invalid",
        ),
    )


def _audit(raw: str, context: AuditContext | None = None):
    configuration = FortiGateParser().parse(raw)
    findings = AuditEngine(default_registry()).run(configuration, context=context)
    return {finding.control_id: finding for finding in findings}


PASS_CONFIG = """
config system admin
    edit "vendor-admin"
        set password ENC synthetic-placeholder
        set two-factor email
        set email-to "support@example.invalid"
    next
    edit "managed-pki"
        set peer-group "vendor-pki-group"
    next
end
config system interface
    edit "admin-loop"
        set type loopback
        set ip 192.0.2.1 255.255.255.255
    next
end
config firewall address
    edit "trusted-admin-source"
        set type fqdn
        set fqdn "admin.example.invalid"
    next
end
config firewall addrgrp
    edit "trusted-admin-sources"
        set member "trusted-admin-source"
    next
end
config firewall vip
    edit "admin-vip"
        set extintf "any"
        set extip 192.0.2.2
        set mappedip "192.0.2.1"
    next
end
config firewall policy
    edit 100
        set srcintf "port1"
        set dstintf "admin-loop"
        set srcaddr "trusted-admin-sources"
        set dstaddr "admin-vip"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
end
config system dns-database
    edit "admin.example.invalid"
    next
end
"""


@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_legacy_admin_controls_pass_through_parser_engine_registry(control_id: str) -> None:
    finding = _audit(PASS_CONFIG, _context())[control_id]

    assert finding.status is AuditStatus.PASS
    assert finding.rule_provenance == "legacy_v1"


@pytest.mark.parametrize(
    ("control_id", "config"),
    (
        (
            "IAM-LEGACY-ADMIN-001",
            PASS_CONFIG.replace("set two-factor email", "set two-factor disable"),
        ),
        (
            "IAM-LEGACY-PKI-REMOVAL-001",
            PASS_CONFIG.replace('edit "managed-pki"', 'edit "legacy-pki"'),
        ),
        (
            "IAM-LEGACY-PKI-PRESENCE-001",
            PASS_CONFIG.replace('edit "managed-pki"', 'edit "other-pki"'),
        ),
        (
            "NET-LEGACY-ADMIN-LOOPBACK-001",
            PASS_CONFIG.replace("set type loopback", "set type physical"),
        ),
        (
            "DNS-LEGACY-DATABASE-001",
            PASS_CONFIG.replace(
                'edit "admin.example.invalid"\n    next\nend',
                'edit "other.example.invalid"\n    next\nend',
                1,
            ),
        ),
    ),
)
def test_legacy_admin_controls_fail_through_parser_engine_registry(
    control_id: str, config: str
) -> None:
    assert _audit(config, _context())[control_id].status is AuditStatus.FAIL


@pytest.mark.parametrize("control_id", CONTROL_IDS)
def test_legacy_admin_controls_are_unknown_without_operator_policy(control_id: str) -> None:
    finding = _audit(PASS_CONFIG)[control_id]

    assert finding.status is AuditStatus.UNKNOWN
    assert finding.rule_provenance == "legacy_v1"


def test_registry_appends_legacy_admin_controls_in_stable_order() -> None:
    controls = default_registry()
    ids = tuple(
        finding.control_id
        for finding in AuditEngine(controls).run(FortiGateParser().parse(PASS_CONFIG), _context())
    )

    assert ids[43:48] == CONTROL_IDS
    assert len(controls) == 60
    assert len(ids) == len(set(ids))
