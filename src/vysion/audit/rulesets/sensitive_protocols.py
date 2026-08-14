from __future__ import annotations

import json
from importlib import resources
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RulesetRange(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    start: int = Field(ge=0, le=65535)
    end: int = Field(ge=0, le=65535)

    @model_validator(mode="before")
    @classmethod
    def accept_json_range(cls, value: object) -> object:
        if isinstance(value, list) and len(value) == 2:
            return {"start": value[0], "end": value[1]}
        return value


class TransportRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol: Literal["tcp", "udp"]
    ranges: tuple[RulesetRange, ...]


class SensitiveProtocolRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    transports: tuple[TransportRule, ...]


class SensitiveProtocolRuleset(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: str
    protocols: tuple[SensitiveProtocolRule, ...]


def load_sensitive_protocol_ruleset() -> SensitiveProtocolRuleset:
    payload = (
        resources.files("vysion.audit.rulesets").joinpath("sensitive_protocols.json").read_text()
    )
    decoded = json.loads(payload)
    return SensitiveProtocolRuleset.model_validate(decoded)
