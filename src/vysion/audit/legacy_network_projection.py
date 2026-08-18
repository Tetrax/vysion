from __future__ import annotations

from dataclasses import dataclass

from vysion.audit.models import (
    AddressGroup,
    AddressObject,
    EvidenceCertainty,
    FortiGateConfiguration,
    ObjectReference,
    ProofState,
    StaticRoute,
    StructuralDirective,
    StructuralDocument,
    StructuralEntry,
)


@dataclass(frozen=True)
class LegacyNetworkProjection:
    address_objects: tuple[AddressObject, ...] = ()
    address_groups: tuple[AddressGroup, ...] = ()
    static_routes: tuple[StaticRoute, ...] = ()


def _directives(entry: StructuralEntry) -> tuple[dict[str, StructuralDirective], set[str]]:
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
    return result, invalidated


def _single(directives: dict[str, StructuralDirective], key: str) -> str | None:
    directive = directives.get(key)
    return directive.tokens[0] if directive is not None and len(directive.tokens) == 1 else None


def _collisions(entries: tuple[StructuralEntry, ...]) -> frozenset[str]:
    counts: dict[str, int] = {}
    for entry in entries:
        key = entry.name.casefold()
        counts[key] = counts.get(key, 0) + 1
    return frozenset(key for key, count in counts.items() if count > 1)


def project_legacy_network(document: StructuralDocument) -> LegacyNetworkProjection:
    addresses: list[AddressObject] = []
    groups: list[AddressGroup] = []
    routes: list[StaticRoute] = []
    route_destinations: dict[str, int] = {}

    for section in document.sections:
        collisions = _collisions(section.entries)
        if section.name == "firewall address":
            for entry in section.entries:
                directives, invalidated = _directives(entry)
                address_type = _single(directives, "type")
                proven = (
                    section.certainty is EvidenceCertainty.CERTAIN
                    and entry.certainty is EvidenceCertainty.CERTAIN
                    and entry.name.casefold() not in collisions
                    and not invalidated
                    and address_type is not None
                )
                addresses.append(
                    AddressObject(
                        name=entry.name,
                        address_type=address_type.casefold() if address_type else None,
                        fqdn=_single(directives, "fqdn"),
                        parsed_keys=frozenset(directives),
                        proof_state=ProofState.PROVEN if proven else ProofState.UNKNOWN,
                    )
                )
        elif section.name == "firewall addrgrp":
            for entry in section.entries:
                directives, invalidated = _directives(entry)
                member = directives.get("member")
                groups.append(
                    AddressGroup(
                        name=entry.name,
                        members=tuple(
                            ObjectReference(
                                object_type="firewall-address",
                                name=name,
                                relation="address-member",
                            )
                            for name in (member.tokens if member else ())
                        ),
                        parsed_keys=frozenset(directives),
                        proof_state=(
                            ProofState.PROVEN
                            if section.certainty is EvidenceCertainty.CERTAIN
                            and entry.certainty is EvidenceCertainty.CERTAIN
                            and entry.name.casefold() not in collisions
                            and not invalidated
                            and member is not None
                            else ProofState.UNKNOWN
                        ),
                    )
                )
        elif section.name == "router static":
            for entry in section.entries:
                directives, invalidated = _directives(entry)
                destination = _single(directives, "dstaddr")
                blackhole = _single(directives, "blackhole")
                distance_value = _single(directives, "distance")
                try:
                    distance = int(distance_value) if distance_value is not None else None
                except ValueError:
                    distance = None
                    invalidated.add("distance")
                destination_reference = (
                    ObjectReference(
                        object_type="firewall-address",
                        name=destination,
                        relation="static-route-destination",
                    )
                    if destination is not None
                    else None
                )
                routes.append(
                    StaticRoute(
                        route_id=entry.name,
                        destination=destination_reference,
                        blackhole=(
                            blackhole.casefold() == "enable"
                            if blackhole is not None
                            and blackhole.casefold() in {"enable", "disable"}
                            else None
                        ),
                        distance=distance,
                        parsed_keys=frozenset(directives),
                        invalidated_keys=frozenset(invalidated),
                        proof_state=(
                            ProofState.PROVEN
                            if section.certainty is EvidenceCertainty.CERTAIN
                            and entry.certainty is EvidenceCertainty.CERTAIN
                            and entry.name.casefold() not in collisions
                            and not invalidated
                            else ProofState.UNKNOWN
                        ),
                    )
                )
                if destination is not None:
                    key = destination.casefold()
                    route_destinations[key] = route_destinations.get(key, 0) + 1

    duplicated_destinations = {
        destination for destination, count in route_destinations.items() if count > 1
    }
    if duplicated_destinations:
        routes = [
            route.model_copy(update={"proof_state": ProofState.UNKNOWN})
            if route.destination is not None
            and route.destination.name.casefold() in duplicated_destinations
            else route
            for route in routes
        ]
    return LegacyNetworkProjection(tuple(addresses), tuple(groups), tuple(routes))


def apply_legacy_network_projection(
    configuration: FortiGateConfiguration,
    projection: LegacyNetworkProjection,
) -> FortiGateConfiguration:
    return configuration.model_copy(
        update={
            "address_objects": projection.address_objects,
            "address_groups": projection.address_groups,
            "static_routes": projection.static_routes,
        }
    )
