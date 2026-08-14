from vysion.audit.models import (
    EvidenceCertainty,
    EvidenceItem,
    StructuralDirective,
    StructuralDocument,
    StructuralEntry,
    StructuralSection,
)


def section_for(document: StructuralDocument, name: str) -> StructuralSection | None:
    return document.section(name)


def entry_for(
    section: StructuralSection | None,
    name: str,
) -> StructuralEntry | None:
    if section is None:
        return None
    return next((entry for entry in section.entries if entry.name == name), None)


def directive_for(
    directives: tuple[StructuralDirective, ...],
    name: str,
) -> StructuralDirective | None:
    return next(
        (
            directive
            for directive in directives
            if directive.name == name
            and not directive.mutation
            and directive.certainty is EvidenceCertainty.CERTAIN
        ),
        None,
    )


def evidence_for_directive(
    document: StructuralDocument,
    section_name: str,
    directive_name: str,
    *,
    entry_name: str | None = None,
    certainty: EvidenceCertainty | None = None,
) -> EvidenceItem:
    section = section_for(document, section_name)
    entry = entry_for(section, entry_name) if entry_name is not None else None
    directives = entry.directives if entry is not None else section.directives if section else ()
    directive = directive_for(directives, directive_name)
    source_line = (
        directive.line
        if directive is not None
        else entry.line
        if entry is not None
        else section.line
        if section is not None
        else None
    )
    source_certainty = (
        directive.certainty
        if directive is not None
        else EvidenceCertainty.AMBIGUOUS
        if section is not None or entry is not None
        else EvidenceCertainty.INVALID
    )
    if section is not None and section.certainty is not EvidenceCertainty.CERTAIN:
        source_certainty = EvidenceCertainty.AMBIGUOUS
    if entry is not None and entry.certainty is not EvidenceCertainty.CERTAIN:
        source_certainty = EvidenceCertainty.AMBIGUOUS
    return EvidenceItem(
        section=section_name,
        entry=entry_name,
        directive=directive_name,
        tokens=directive.tokens if directive is not None else (),
        line=source_line,
        certainty=certainty or source_certainty,
        defaulted=directive.defaulted if directive is not None else False,
    )


def evidence_for_section(
    document: StructuralDocument,
    section_name: str,
    *,
    certainty: EvidenceCertainty | None = None,
) -> EvidenceItem:
    """Represent the complete parsed section itself as structured evidence.

    This is the correct evidence form for absence controls: the proof is the
    exhaustive, certain namespace and its enumerated entries, not a fabricated
    directive that could never exist in the FortiGate configuration.
    """
    section = section_for(document, section_name)
    return EvidenceItem(
        section=section_name,
        tokens=tuple(entry.name for entry in section.entries) if section else (),
        line=section.line if section else None,
        certainty=certainty
        or (section.certainty if section is not None else EvidenceCertainty.INVALID),
    )


def evidence_for_entry(
    document: StructuralDocument,
    section_name: str,
    entry_name: str,
    *,
    certainty: EvidenceCertainty | None = None,
) -> EvidenceItem:
    """Represent an entry's explicit presence without inventing a directive."""
    section = section_for(document, section_name)
    entry = entry_for(section, entry_name)
    source_certainty = (
        entry.certainty
        if entry is not None
        else EvidenceCertainty.AMBIGUOUS
        if section is not None
        else EvidenceCertainty.INVALID
    )
    return EvidenceItem(
        section=section_name,
        entry=entry_name,
        line=entry.line if entry else section.line if section else None,
        certainty=certainty or source_certainty,
    )


def evidence_for_complete_backup() -> EvidenceItem:
    return EvidenceItem(
        section="backup-metadata",
        directive="complete-backup",
        tokens=("true",),
        line=1,
        certainty=EvidenceCertainty.CERTAIN,
    )
