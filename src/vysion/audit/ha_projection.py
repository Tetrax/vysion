from __future__ import annotations

from dataclasses import dataclass

from vysion.audit.models import (
    EvidenceCertainty,
    FortiGateConfiguration,
    HaSettings,
    ProofState,
    StructuralDirective,
    StructuralDocument,
)

_HA_KEYS = frozenset(
    {
        "group-name",
        "session-pickup",
        "session-pickup-connectionless",
        "session-pickup-expectation",
        "hbdev",
        "override",
        "override-wait-time",
    }
)


@dataclass(frozen=True)
class HaProjection:
    settings: HaSettings | None = None


def _certain_values(
    directives: tuple[StructuralDirective, ...],
    invalidated_keys: frozenset[str],
) -> tuple[dict[str, StructuralDirective], set[str]]:
    values: dict[str, StructuralDirective] = {}
    invalidated = set(invalidated_keys)
    for directive in directives:
        if directive.name not in _HA_KEYS or directive.name in invalidated:
            continue
        if (
            directive.mutation
            or directive.certainty is not EvidenceCertainty.CERTAIN
            or directive.name in values
        ):
            invalidated.add(directive.name)
            values.pop(directive.name, None)
        else:
            values[directive.name] = directive
    return values, invalidated


def _single(
    values: dict[str, StructuralDirective], key: str, invalidated: set[str]
) -> str | None:
    directive = values.get(key)
    if directive is None:
        return None
    if len(directive.tokens) != 1:
        invalidated.add(key)
        return None
    return directive.tokens[0].casefold()


def _heartbeat_interfaces(
    values: dict[str, StructuralDirective], invalidated: set[str]
) -> tuple[str, ...]:
    directive = values.get("hbdev")
    if directive is None:
        return ()
    tokens = directive.tokens
    if not tokens or len(tokens) % 2:
        invalidated.add("hbdev")
        return ()
    interfaces: list[str] = []
    for index in range(0, len(tokens), 2):
        interface, priority = tokens[index : index + 2]
        try:
            int(priority, 10)
        except ValueError:
            invalidated.add("hbdev")
            return ()
        interfaces.append(interface)
    if len({name.casefold() for name in interfaces}) != len(interfaces):
        invalidated.add("hbdev")
        return ()
    return tuple(interfaces)


def project_ha(document: StructuralDocument) -> HaProjection:
    section = document.section("system ha")
    if section is None:
        return HaProjection()
    values, invalidated = _certain_values(section.directives, section.invalidated_keys)
    group_name = _single(values, "group-name", invalidated)
    session_pickup = _single(values, "session-pickup", invalidated)
    connectionless = _single(values, "session-pickup-connectionless", invalidated)
    expectation = _single(values, "session-pickup-expectation", invalidated)
    heartbeat_interfaces = _heartbeat_interfaces(values, invalidated)
    override = _single(values, "override", invalidated)
    wait_token = _single(values, "override-wait-time", invalidated)
    override_wait_time: int | None = None
    if wait_token is not None:
        try:
            override_wait_time = int(wait_token, 10)
        except ValueError:
            invalidated.add("override-wait-time")
    parsed_keys = frozenset(set(values) - invalidated)
    proof_state = (
        ProofState.PROVEN
        if section.certainty is EvidenceCertainty.CERTAIN
        and not section.entries
        and not section.children
        and not invalidated
        and "group-name" in parsed_keys
        else ProofState.UNKNOWN
    )
    return HaProjection(
        settings=HaSettings(
            group_name=group_name,
            session_pickup=session_pickup,
            session_pickup_connectionless=connectionless,
            session_pickup_expectation=expectation,
            heartbeat_interfaces=heartbeat_interfaces,
            override=override,
            override_wait_time=override_wait_time,
            parsed_keys=parsed_keys,
            invalidated_keys=frozenset(invalidated),
            proof_state=proof_state,
        )
    )


def apply_ha_projection(
    configuration: FortiGateConfiguration, projection: HaProjection
) -> FortiGateConfiguration:
    return configuration.model_copy(update={"ha_settings": projection.settings})
