from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditContext, AuditStatus, ContextProvenance
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

UTM_EXTERNAL_STRONG = """config system fortisandbox
    set sandbox-region Europe
end
config system fortiguard
    set fortiguard-anycast disable
end
"""


def _findings(raw: str, *, licensed: bool | None = True):
    configuration = FortiGateParser().parse(raw)
    context = AuditContext(
        utm_license=licensed,
        operator_provenance=(
            ContextProvenance(source="operator", method="license-check")
            if licensed is not None
            else None
        ),
    )
    return {
        finding.control_id: finding
        for finding in AuditEngine(default_registry()).run(configuration, context=context)
    }


def test_utm_external_settings_trace_parser_registry() -> None:
    findings = _findings(UTM_EXTERNAL_STRONG)

    assert findings["UTM-FORTISANDBOX-CLOUD-001"].status is AuditStatus.PASS
    assert findings["UTM-FORTIGUARD-ANYCAST-001"].status is AuditStatus.PASS


def test_utm_external_certain_legacy_violations_fail() -> None:
    raw = UTM_EXTERNAL_STRONG.replace("Europe", "Global").replace(
        "fortiguard-anycast disable", "fortiguard-anycast enable"
    )
    findings = _findings(raw)

    assert findings["UTM-FORTISANDBOX-CLOUD-001"].status is AuditStatus.FAIL
    assert findings["UTM-FORTIGUARD-ANYCAST-001"].status is AuditStatus.FAIL


def test_utm_external_missing_or_unlicensed_evidence_never_passes() -> None:
    missing = _findings("config system global\nend\n", licensed=None)
    unlicensed = _findings(UTM_EXTERNAL_STRONG, licensed=False)

    for findings in (missing, unlicensed):
        assert findings["UTM-FORTISANDBOX-CLOUD-001"].status is not AuditStatus.PASS
        assert findings["UTM-FORTIGUARD-ANYCAST-001"].status is not AuditStatus.PASS


def test_mail_filter_usage_is_a_certain_failure_through_registry() -> None:
    raw = """config firewall policy
    edit 10
        set emailfilter-profile "mail-filter"
    next
end
"""

    finding = _findings(raw)["UTM-MAIL-FILTER-USAGE-001"]

    assert finding.status is AuditStatus.FAIL
    assert finding.affected_objects[0].name == "10"
    assert finding.evidence_items[0].directive == "emailfilter-profile"


def test_mail_filter_absence_in_certain_policies_passes() -> None:
    raw = """config firewall policy
    edit 10
        set srcintf "lan"
        set dstintf "wan1"
    next
end
"""

    assert _findings(raw)["UTM-MAIL-FILTER-USAGE-001"].status is AuditStatus.PASS


def test_mail_filter_absent_or_mutated_policy_evidence_is_unknown() -> None:
    missing = _findings("config system global\nend\n")["UTM-MAIL-FILTER-USAGE-001"]
    mutated = _findings(
        """config firewall policy
    edit 10
        set emailfilter-profile "mail-filter"
        unset emailfilter-profile
    next
end
"""
    )["UTM-MAIL-FILTER-USAGE-001"]

    assert missing.status is AuditStatus.UNKNOWN
    assert mutated.status is AuditStatus.UNKNOWN
