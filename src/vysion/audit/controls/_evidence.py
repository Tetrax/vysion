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


def _matching_entries(
    section: StructuralSection,
    name: str,
) -> tuple[StructuralEntry, ...]:
    normalized_name = name.casefold()
    matches = tuple(
        entry for entry in section.entries if entry.name.casefold() == normalized_name
    )
    nested_matches = tuple(
        entry
        for child in section.children
        for entry in _matching_entries(child, name)
    )
    entry_child_matches = tuple(
        entry
        for parent_entry in section.entries
        for child in parent_entry.children
        for entry in _matching_entries(child, name)
    )
    return matches + nested_matches + entry_child_matches


def entry_for(
    section: StructuralSection | None,
    name: str,
) -> StructuralEntry | None:
    if section is None:
        return None
    matches = _matching_entries(section, name)
    return matches[0] if len(matches) == 1 else None


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


def _effective_certainty(
    source_certainty: EvidenceCertainty,
    requested_certainty: EvidenceCertainty | None,
) -> EvidenceCertainty:
    if source_certainty is not EvidenceCertainty.CERTAIN:
        return source_certainty
    return requested_certainty or source_certainty


def _sdwan_member_directive(
    document: StructuralDocument,
    zone_name: str,
    interface_name: str,
) -> tuple[str, StructuralDirective] | None:
    section = section_for(document, "system sdwan")
    if section is None or section.certainty is not EvidenceCertainty.CERTAIN:
        return None
    zone_sections = tuple(
        child for child in section.children if child.name.casefold() == "zone"
    )
    members_sections = tuple(
        child for child in section.children if child.name.casefold() == "members"
    )
    if len(zone_sections) != 1 or len(members_sections) != 1:
        return None
    zone_section = zone_sections[0]
    members_section = members_sections[0]
    if (
        zone_section.certainty is not EvidenceCertainty.CERTAIN
        or members_section.certainty is not EvidenceCertainty.CERTAIN
    ):
        return None
    zone_entries = tuple(
        entry
        for entry in zone_sections[0].entries
        if entry.name.casefold() == zone_name.casefold()
    )
    if len(zone_entries) != 1:
        return None
    zone_entry = zone_entries[0]
    if zone_entry.certainty is not EvidenceCertainty.CERTAIN:
        return None
    candidates: list[tuple[str, StructuralDirective]] = []
    for member in members_section.entries:
        if member.certainty is not EvidenceCertainty.CERTAIN:
            continue
        directives = tuple(
            directive
            for directive in member.directives
            if directive.name == "interface"
        )
        if (
            len(directives) != 1
            or directives[0].certainty is not EvidenceCertainty.CERTAIN
            or directives[0].mutation
            or len(directives[0].tokens) != 1
            or directives[0].tokens[0].casefold() != interface_name.casefold()
        ):
            continue
        zone_directives = tuple(
            directive for directive in member.directives if directive.name == "zone"
        )
        if zone_directives and (
            len(zone_directives) != 1
            or zone_directives[0].certainty is not EvidenceCertainty.CERTAIN
            or zone_directives[0].mutation
            or len(zone_directives[0].tokens) != 1
            or zone_directives[0].tokens[0].casefold() != zone_name.casefold()
        ):
            continue
        if not zone_directives and len(zone_section.entries) != 1:
            continue
        candidates.append((member.name, directives[0]))
    return candidates[0] if len(candidates) == 1 else None


def evidence_for_sdwan_member(
    document: StructuralDocument,
    zone_name: str,
    interface_name: str,
    *,
    certainty: EvidenceCertainty | None = None,
) -> EvidenceItem | None:
    match = _sdwan_member_directive(document, zone_name, interface_name)
    if match is None:
        return None
    member_name, directive = match
    return EvidenceItem(
        section="system sdwan -> members",
        entry=member_name,
        directive="interface",
        tokens=directive.tokens,
        line=directive.line,
        certainty=_effective_certainty(directive.certainty, certainty),
        defaulted=directive.defaulted,
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
    if entry_name is not None:
        directives = entry.directives if entry is not None else ()
    else:
        directives = section.directives if section else ()
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
        certainty=_effective_certainty(source_certainty, certainty),
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
    source_certainty = (
        section.certainty if section is not None else EvidenceCertainty.INVALID
    )
    return EvidenceItem(
        section=section_name,
        tokens=tuple(entry.name for entry in section.entries) if section else (),
        line=section.line if section else None,
        certainty=_effective_certainty(source_certainty, certainty),
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
        certainty=_effective_certainty(source_certainty, certainty),
    )


def evidence_for_complete_backup() -> EvidenceItem:
    return EvidenceItem(
        section="backup-metadata",
        directive="complete-backup",
        tokens=("true",),
        line=1,
        certainty=EvidenceCertainty.CERTAIN,
    )
