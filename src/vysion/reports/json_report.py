from datetime import UTC, datetime
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, field_validator, model_validator

from vysion.adapters.fortiguard import FortiGuardResult
from vysion.audit.models import AuditFinding


class JsonAuditReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: int = 1
    report_id: UUID
    created_at: AwareDatetime
    expires_at: AwareDatetime
    source_name: str
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
