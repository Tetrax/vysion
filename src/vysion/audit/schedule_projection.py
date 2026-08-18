from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime

from vysion.audit.models import (
    EvidenceCertainty,
    FortiGateConfiguration,
    ObjectReference,
    OnetimeSchedule,
    ProofState,
    RecurringSchedule,
    ScheduleGroup,
    StructuralDocument,
    StructuralEntry,
)


@dataclass(frozen=True)
class ScheduleProjection:
    onetime: tuple[OnetimeSchedule, ...] = ()
    recurring: tuple[RecurringSchedule, ...] = ()
    groups: tuple[ScheduleGroup, ...] = ()


def _directives(entry: StructuralEntry, allowed: frozenset[str]):
    result = {}
    invalid = set(entry.invalidated_keys)
    for directive in entry.directives:
        if directive.name not in allowed or directive.name in invalid:
            continue
        if (
            directive.mutation
            or directive.certainty is not EvidenceCertainty.CERTAIN
            or directive.name in result
        ):
            invalid.add(directive.name)
            result.pop(directive.name, None)
        else:
            result[directive.name] = directive
    return result


def _onetime(entry: StructuralEntry) -> OnetimeSchedule:
    directives = _directives(entry, frozenset({"end"}))
    tokens = directives["end"].tokens if "end" in directives else ()
    end = None
    if len(tokens) == 2:
        with suppress(ValueError):
            end = datetime.strptime(" ".join(tokens), "%H:%M %Y/%m/%d")
    proven = (
        entry.certainty is EvidenceCertainty.CERTAIN
        and end is not None
        and "end" not in entry.invalidated_keys
    )
    return OnetimeSchedule(
        name=entry.name,
        end=end,
        parsed_keys=frozenset(directives),
        proof_state=ProofState.PROVEN if proven else ProofState.UNKNOWN,
    )


def project_schedules(document: StructuralDocument) -> ScheduleProjection:
    onetime: list[OnetimeSchedule] = []
    recurring: list[RecurringSchedule] = []
    groups: list[ScheduleGroup] = []
    for section in document.sections:
        if section.name == "firewall schedule onetime":
            onetime.extend(_onetime(entry) for entry in section.entries)
        elif section.name == "firewall schedule recurring":
            recurring.extend(
                RecurringSchedule(
                    name=entry.name,
                    proof_state=(
                        ProofState.PROVEN
                        if section.certainty is EvidenceCertainty.CERTAIN
                        and entry.certainty is EvidenceCertainty.CERTAIN
                        else ProofState.UNKNOWN
                    ),
                )
                for entry in section.entries
                if entry.name.casefold() != "always"
            )
        elif section.name == "firewall schedule group":
            for entry in section.entries:
                directives = _directives(entry, frozenset({"member"}))
                members = directives["member"].tokens if "member" in directives else ()
                groups.append(
                    ScheduleGroup(
                        name=entry.name,
                        members=tuple(
                            ObjectReference(
                                object_type="schedule", name=name, relation="schedule-member"
                            )
                            for name in members
                        ),
                        proof_state=(
                            ProofState.PROVEN
                            if section.certainty is EvidenceCertainty.CERTAIN
                            and entry.certainty is EvidenceCertainty.CERTAIN
                            and "member" in directives
                            and bool(members)
                            else ProofState.UNKNOWN
                        ),
                    )
                )
    return ScheduleProjection(tuple(onetime), tuple(recurring), tuple(groups))


def apply_schedule_projection(
    configuration: FortiGateConfiguration, projection: ScheduleProjection
) -> FortiGateConfiguration:
    return configuration.model_copy(
        update={
            "onetime_schedules": projection.onetime,
            "recurring_schedules": projection.recurring,
            "schedule_groups": projection.groups,
        }
    )
