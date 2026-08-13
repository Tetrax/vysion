from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AuditStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class Interface(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    address: str | None = None
    allowaccess: frozenset[str] = Field(default_factory=frozenset)
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)


class Administrator(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    two_factor: str | None = None


class FortiGateConfiguration(BaseModel):
    model_config = ConfigDict(frozen=True)

    hostname: str | None = None
    interfaces: tuple[Interface, ...] = ()
    administrators: tuple[Administrator, ...] = ()
    parsed_sections: frozenset[str] = Field(default_factory=frozenset)
    parsed_entry_sections: frozenset[str] = Field(default_factory=frozenset)
    parsed_value_sections: frozenset[str] = Field(default_factory=frozenset)


class AuditFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    control_id: str
    title: str
    status: AuditStatus
    evidence: tuple[str, ...] = ()
    message: str
    risk: str | None = None
    recommendation: str | None = None
