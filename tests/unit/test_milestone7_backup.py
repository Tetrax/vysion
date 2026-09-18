from vysion.audit.engine import AuditEngine
from vysion.audit.models import (
    AuditPriority,
    AuditStatus,
    EvidenceCertainty,
    FortiGateConfiguration,
    StructuralDirective,
    StructuralDocument,
    StructuralSection,
)
from vysion.audit.parser import FortiGateParser
from vysion.audit.registry import default_registry

BACKUP_ENABLED = """config system global
    set revision-backup-on-logout enable
    set revision-image-auto-backup enable
end
"""


def _finding(raw: str):
    findings = AuditEngine(default_registry()).run(FortiGateParser().parse(raw))
    return next(
        (finding for finding in findings if finding.control_id == "SYS-BACKUP-AUTO-001"),
        None,
    )


def test_both_explicit_revision_backups_enable_the_registered_control() -> None:
    finding = _finding(BACKUP_ENABLED)

    assert finding is not None
    assert finding.status is AuditStatus.PASS
    assert finding.category == "system"
    assert finding.priority is AuditPriority.P1
    assert [item.directive for item in finding.evidence_items] == [
        "revision-backup-on-logout",
        "revision-image-auto-backup",
    ]
    assert [item.line for item in finding.evidence_items] == [2, 3]
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_explicitly_disabled_revision_backup_fails_with_precise_action() -> None:
    raw = """config system global
    set revision-backup-on-logout disable
    set revision-image-auto-backup enable
end
"""

    finding = _finding(raw)

    assert finding is not None
    assert finding.status is AuditStatus.FAIL
    assert finding.applicability.value == "applicable"
    assert finding.evidence_items[0].certainty is EvidenceCertainty.CERTAIN
    # Client wording names the disabled option in business French; the raw
    # FortiOS directive names stay in the machine evidence.
    assert "sauvegarde à la déconnexion d'un administrateur" in finding.message
    assert "revision-backup-on-logout" not in finding.message
    remediation = finding.remediation or ""
    assert "sauvegarde automatique de révision" in remediation
    assert "revision-backup-on-logout" not in remediation


def test_invalid_structural_document_cannot_prove_enabled_revision_backups() -> None:
    document = StructuralDocument(
        valid=False,
        certainty=EvidenceCertainty.AMBIGUOUS,
        sections=(
            StructuralSection(
                name="system global",
                line=1,
                directives=(
                    StructuralDirective(
                        name="revision-backup-on-logout",
                        tokens=("enable",),
                        line=2,
                    ),
                    StructuralDirective(
                        name="revision-image-auto-backup",
                        tokens=("enable",),
                        line=3,
                    ),
                ),
            ),
        ),
    )

    configuration = FortiGateConfiguration(document=document)
    finding = next(
        item
        for item in AuditEngine(default_registry()).run(configuration)
        if item.control_id == "SYS-BACKUP-AUTO-001"
    )

    assert finding.status is AuditStatus.UNKNOWN


def test_missing_system_global_namespace_is_unknown() -> None:
    finding = _finding("config system interface\nend\n")

    assert finding is not None
    assert finding.status is AuditStatus.UNKNOWN
    assert all(item.certainty is EvidenceCertainty.INVALID for item in finding.evidence_items)


def test_single_explicit_enable_without_its_pair_is_unknown() -> None:
    raw = """config system global
    set revision-backup-on-logout enable
end
"""

    finding = _finding(raw)

    assert finding is not None
    assert finding.status is AuditStatus.UNKNOWN
    assert finding.evidence_items[0].certainty is EvidenceCertainty.CERTAIN
    assert finding.evidence_items[1].certainty is EvidenceCertainty.AMBIGUOUS


def test_revision_directive_without_value_is_unknown() -> None:
    raw = """config system global
    set revision-backup-on-logout enable
    set revision-image-auto-backup
end
"""

    finding = _finding(raw)

    assert finding is not None
    assert finding.status is AuditStatus.UNKNOWN
    assert all(
        item.certainty is not EvidenceCertainty.CERTAIN
        for item in finding.evidence_items[1:]
    )


def test_revision_mutation_invalidates_an_enable_proof() -> None:
    raw = """config system global
    set revision-backup-on-logout enable
    append revision-backup-on-logout disable
    set revision-image-auto-backup enable
end
"""

    finding = _finding(raw)

    assert finding is not None
    assert finding.status is AuditStatus.UNKNOWN
    assert all(item.certainty is not EvidenceCertainty.CERTAIN for item in finding.evidence_items)


def test_revision_unset_does_not_reuse_a_stale_enable() -> None:
    raw = """config system global
    set revision-backup-on-logout enable
    unset revision-backup-on-logout
    set revision-image-auto-backup enable
end
"""

    finding = _finding(raw)

    assert finding is not None
    assert finding.status is AuditStatus.UNKNOWN
    assert finding.evidence_items[0].certainty is not EvidenceCertainty.CERTAIN
    assert finding.evidence_items[1].certainty is EvidenceCertainty.CERTAIN


def test_noncanonical_revision_key_is_ambiguous_not_proven() -> None:
    raw = """config system global
    set Revision-backup-on-logout enable
    set revision-image-auto-backup enable
end
"""

    finding = _finding(raw)

    assert finding is not None
    assert finding.status is AuditStatus.UNKNOWN
    assert finding.evidence_items[0].certainty is EvidenceCertainty.AMBIGUOUS


def test_both_explicitly_disabled_revision_backups_fail() -> None:
    raw = """config system global
    set revision-backup-on-logout disable
    set revision-image-auto-backup disable
end
"""

    finding = _finding(raw)

    assert finding is not None
    assert finding.status is AuditStatus.FAIL
    assert finding.evidence == (
        "revision-backup-on-logout: disable",
        "revision-image-auto-backup: disable",
    )
    assert all(item.certainty is EvidenceCertainty.CERTAIN for item in finding.evidence_items)
