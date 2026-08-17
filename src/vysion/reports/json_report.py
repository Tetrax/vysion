from datetime import UTC, datetime
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from vysion.adapters.fortiguard import FortiGuardResult
from vysion.audit.models import AuditContext, AuditFinding


class EquipmentMetadata(BaseModel):
    """Business-safe equipment facts projected from the typed configuration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    hostname: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None
    interface_names: tuple[str, ...] = ()
    zone_names: tuple[str, ...] = ()
    sdwan_zone_names: tuple[str, ...] = ()
    interface_zone_relations: tuple[str, ...] = ()


class AccountMetadata(BaseModel):
    """Minimal account facts safe to include in the report."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    kind: str
    two_factor: str | None = None
    peer_auth: str | None = None


class JsonAuditReport(BaseModel):
    """Versioned canonical report; every other renderer consumes this model."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(default=2, frozen=True)
    report_id: UUID
    created_at: AwareDatetime
    expires_at: AwareDatetime
    source_name: str
    context: AuditContext = Field(default_factory=AuditContext)
    equipment: EquipmentMetadata = Field(default_factory=EquipmentMetadata)
    accounts: tuple[AccountMetadata, ...] = ()
    fortiguard: FortiGuardResult
    findings: tuple[AuditFinding, ...]

    @field_validator("created_at", "expires_at")
    @classmethod
    def normalize_timestamp_to_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def expiration_follows_creation(self) -> "JsonAuditReport":
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        return self
