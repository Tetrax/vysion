from __future__ import annotations

from dataclasses import dataclass

from vysion.audit.models import (
    AddressGroup,
    AddressObject,
    DnsDatabaseEntry,
    EvidenceCertainty,
    FortiGateConfiguration,
    ObjectReference,
    ProofState,
    StructuralDirective,
    StructuralDocument,
    StructuralEntry,
)


@dataclass(frozen=True)
class LegacyAdminProjection:
    address_objects: tuple[AddressObject, ...] = ()
    address_groups: tuple[AddressGroup, ...] = ()
    dns_database_entries: tuple[DnsDatabaseEntry, ...] = ()


def _directives(entry: StructuralEntry) -> dict[str, StructuralDirective]:
    result: dict[str, StructuralDirective] = {}
    invalidated = set(entry.invalidated_keys)
    for directive in entry.directives:
        if directive.name in invalidated:
            continue
        if (
            directive.mutation
            or directive.certainty is not EvidenceCertainty.CERTAIN
            or directive.name in result
        ):
            invalidated.add(directive.name)
            result.pop(directive.name, None)
        else:
            result[directive.name] = directive
    return result


def _single(directives: dict[str, StructuralDirective], key: str) -> str | None:
    directive = directives.get(key)
    return directive.tokens[0] if directive is not None and len(directive.tokens) == 1 else None


def project_legacy_admin(document: StructuralDocument) -> LegacyAdminProjection:
    addresses: list[AddressObject] = []
    groups: list[AddressGroup] = []
    dns_entries: list[DnsDatabaseEntry] = []
    for section in document.sections:
        if section.name == "firewall address":
            for entry in section.entries:
                directives = _directives(entry)
                address_type = _single(directives, "type")
                fqdn = _single(directives, "fqdn")
                addresses.append(
                    AddressObject(
                        name=entry.name,
                        address_type=address_type.casefold() if address_type else None,
                        fqdn=fqdn,
                        parsed_keys=frozenset(directives),
                        proof_state=(
                            ProofState.PROVEN
                            if section.certainty is EvidenceCertainty.CERTAIN
                            and entry.certainty is EvidenceCertainty.CERTAIN
                            and address_type is not None
                            and (address_type.casefold() != "fqdn" or fqdn is not None)
                            else ProofState.UNKNOWN
                        ),
                    )
                )
        elif section.name == "firewall addrgrp":
            for entry in section.entries:
                directives = _directives(entry)
                member = directives.get("member")
                members = (
                    tuple(
                        ObjectReference(
                            object_type="firewall-address",
                            name=name,
                            relation="address-member",
                        )
                        for name in member.tokens
                    )
                    if member is not None
                    else ()
                )
                groups.append(
                    AddressGroup(
                        name=entry.name,
                        members=members,
                        parsed_keys=frozenset(directives),
                        proof_state=(
                            ProofState.PROVEN
                            if section.certainty is EvidenceCertainty.CERTAIN
                            and entry.certainty is EvidenceCertainty.CERTAIN
                            and member is not None
                            else ProofState.UNKNOWN
                        ),
                    )
                )
        elif section.name == "system dns-database":
            dns_entries.extend(
                DnsDatabaseEntry(
                    name=entry.name,
                    proof_state=(
                        ProofState.PROVEN
                        if section.certainty is EvidenceCertainty.CERTAIN
                        and entry.certainty is EvidenceCertainty.CERTAIN
                        else ProofState.UNKNOWN
                    ),
                )
                for entry in section.entries
            )
    return LegacyAdminProjection(tuple(addresses), tuple(groups), tuple(dns_entries))


def apply_legacy_admin_projection(
    configuration: FortiGateConfiguration,
    projection: LegacyAdminProjection,
) -> FortiGateConfiguration:
    return configuration.model_copy(
        update={
            "address_objects": projection.address_objects,
            "address_groups": projection.address_groups,
            "dns_database_entries": projection.dns_database_entries,
        }
    )
