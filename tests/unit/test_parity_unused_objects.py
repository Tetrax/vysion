from vysion.audit.engine import AuditEngine
from vysion.audit.models import AuditStatus, EvidenceCertainty
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry


def _unused_finding(raw: str):
    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))
    return next(item for item in findings if item.control_id == "CFG-UNUSED-SERVICE-001")


def test_unused_service_object_is_reported_through_typed_registry() -> None:
    raw = """config firewall service custom
    edit "orphan-service"
        set tcp-portrange 8443
    next
end
config firewall service group
end
config firewall policy
end
"""

    finding = _unused_finding(raw)

    assert finding.status is AuditStatus.FAIL
    assert [(item.object_type, item.name) for item in finding.affected_objects] == [
        ("service", "orphan-service")
    ]
    assert finding.evidence_items
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_used_service_object_passes_when_service_family_is_complete() -> None:
    raw = """config firewall service custom
    edit "web-service"
        set tcp-portrange 443
    next
end
config firewall service group
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "web-service"
    next
end
"""

    assert _unused_finding(raw).status is AuditStatus.PASS


def test_unused_service_stays_unknown_for_collision_or_mutation() -> None:
    collision = """config firewall service custom
    edit "Web"
        set tcp-portrange 443
    next
end
config firewall service group
    edit "web"
        set member "Web"
    next
end
config firewall policy
end
"""
    mutation = """config firewall service custom
    edit "orphan-service"
        set tcp-portrange 8443
        unset tcp-portrange
    next
end
config firewall service group
end
config firewall policy
end
"""

    assert _unused_finding(collision).status is AuditStatus.UNKNOWN
    assert _unused_finding(mutation).status is AuditStatus.UNKNOWN


def test_explicitly_empty_service_family_is_not_applicable() -> None:
    raw = """config firewall service custom
end
config firewall service group
end
config firewall policy
end
"""

    assert _unused_finding(raw).status is AuditStatus.NOT_APPLICABLE
