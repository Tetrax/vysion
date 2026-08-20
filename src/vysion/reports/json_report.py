from datetime import UTC, datetime
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from vysion.adapters.fortiguard import FortiGuardResult
from vysion.audit.models import AuditContext, AuditFinding, DeviceIdentity
from vysion.reports.presentation import AuditPresentation


class JsonAuditReport(BaseModel):
    """Versioned canonical report; every other renderer consumes this model."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(default=2, frozen=True)
    report_id: UUID
    created_at: AwareDatetime
    expires_at: AwareDatetime
    source_name: str
    context: AuditContext = Field(default_factory=AuditContext)
    device_identity: DeviceIdentity | None = None
    fortiguard: FortiGuardResult
    findings: tuple[AuditFinding, ...]
    presentation: AuditPresentation | None = None

    @field_validator("created_at", "expires_at")
    @classmethod
    def normalize_timestamp_to_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def expiration_follows_creation(self) -> "JsonAuditReport":
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        return self
