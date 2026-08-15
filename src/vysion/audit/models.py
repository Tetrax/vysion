from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator


class AuditStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


class AuditPriority(StrEnum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class AuditSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Applicability(StrEnum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class ProofState(StrEnum):
    PROVEN = "proven"
    UNKNOWN = "unknown"
    INVALID = "invalid"


class EvidenceCertainty(StrEnum):
    CERTAIN = "certain"
    AMBIGUOUS = "ambiguous"
    INVALID = "invalid"


class ObjectReference(BaseModel):
    """A typed reference to an object, never an unstructured object name."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    object_type: str = "unknown"
    name: str
    relation: str | None = None


class AffectedObject(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    object_type: str = "unknown"
    reference: ObjectReference | None = None


class RiskAssessment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: str
    impact: str | None = None
    likelihood: str | None = None
    treatment: str | None = None


class EvidenceItem(BaseModel):
    """Structured evidence that can be traced to the secure document."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    section: str | None = None
    entry: str | None = None
    directive: str | None = None
    tokens: tuple[str, ...] = ()
    line: int | None = Field(default=None, ge=1)
    certainty: EvidenceCertainty = EvidenceCertainty.CERTAIN
    defaulted: bool = False

    @property
    def value_tokens(self) -> tuple[str, ...]:
        return self.tokens


class StructuralDirective(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    tokens: tuple[str, ...] = ()
    line: int = Field(ge=1)
    certainty: EvidenceCertainty = EvidenceCertainty.CERTAIN
    mutation: bool = False
    defaulted: bool = False

    @property
    def value_tokens(self) -> tuple[str, ...]:
        return self.tokens


class StructuralEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    line: int = Field(ge=1)
    directives: tuple[StructuralDirective, ...] = ()
    children: tuple["StructuralSection", ...] = ()
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    invalidated_keys: frozenset[str] = Field(default_factory=frozenset)
    certainty: EvidenceCertainty = EvidenceCertainty.CERTAIN


class StructuralSection(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    line: int = Field(ge=1)
    directives: tuple[StructuralDirective, ...] = ()
    entries: tuple[StructuralEntry, ...] = ()
    children: tuple["StructuralSection", ...] = ()
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    invalidated_keys: frozenset[str] = Field(default_factory=frozenset)
    certainty: EvidenceCertainty = EvidenceCertainty.CERTAIN


class StructuralDocument(BaseModel):
    """Generic, raw-text-free parser output used as the only evidence boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_format: str = "fortigate"
    valid: bool = True
    certainty: EvidenceCertainty = EvidenceCertainty.CERTAIN
    sections: tuple[StructuralSection, ...] = ()

    @property
    def parsed_sections(self) -> frozenset[str]:
        return frozenset(section.name for section in self.sections)

    def section(self, name: str) -> StructuralSection | None:
        normalized = name.casefold()
        return next((item for item in self.sections if item.name.casefold() == normalized), None)


class ContextProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str
    operator: str | None = None
    captured_at: Any | None = None
    method: str | None = None


# Explicitly named alias for callers that prefer the domain term.
OperatorContextProvenance = ContextProvenance


class ExternalObservationStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class PsirtObservation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: ExternalObservationStatus
    fortios_version: str
    vulnerabilities: tuple[str, ...] = ()
    source: str
    ruleset_id: str
    ruleset_version: str
    observed_at: datetime | None = None
    complete: bool = False


class AuditContext(BaseModel):
    """Immutable operator/context facts; omitted booleans remain unknown (None)."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    selected_wans: tuple[str, ...] | None = None
    operator_provenance: ContextProvenance | None = None
    client: str | None = Field(default=None, validation_alias=AliasChoices("client", "client_name"))
    site: str | None = Field(default=None, validation_alias=AliasChoices("site", "site_name"))
    ha: bool | None = Field(default=None, validation_alias=AliasChoices("ha", "ha_enabled"))
    mpls: bool | None = Field(default=None, validation_alias=AliasChoices("mpls", "mpls_enabled"))
    utm_license: bool | None = Field(
        default=None,
        validation_alias=AliasChoices("utm_license", "utm_licensed"),
    )
    psirt: PsirtObservation | None = None

    @property
    def client_name(self) -> str | None:
        return self.client

    @property
    def site_name(self) -> str | None:
        return self.site

    @property
    def ha_enabled(self) -> bool | None:
        return self.ha

    @property
    def mpls_enabled(self) -> bool | None:
        return self.mpls

    @property
    def utm_licensed(self) -> bool | None:
        return self.utm_license


class DeviceIdentity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    hostname: str | None = None
    serial_number: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class Interface(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    address: str | None = None
    allowaccess: frozenset[str] = Field(default_factory=frozenset)
    role: str | None = None
    secondary_ips: tuple["SecondaryIP", ...] = ()
    zone: ObjectReference | None = None
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.PROVEN


class SecondaryIP(BaseModel):
    """A secondary address attached to an interface.

    FortiOS permits ``allowaccess`` on a secondary address as well as on the
    parent interface.  Keeping that directive in a typed projection prevents
    controls from accidentally treating the parent directive as proof for the
    nested address.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    address: str | None = None
    allowaccess: frozenset[str] = Field(default_factory=frozenset)
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class Zone(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    interfaces: tuple[ObjectReference, ...] = ()
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class Policy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    policy_id: str = Field(validation_alias=AliasChoices("policy_id", "id"))
    name: str | None = None
    source_interfaces: tuple[ObjectReference, ...] = ()
    destination_interfaces: tuple[ObjectReference, ...] = ()
    object_references: tuple[ObjectReference, ...] = ()
    source_addresses: tuple[ObjectReference, ...] = ()
    destination_addresses: tuple[ObjectReference, ...] = ()
    action: str | None = None
    status: str | None = None
    schedule: str | None = None
    services: tuple[ObjectReference, ...] = ()
    logtraffic: str | None = None
    nat: str | None = None
    utm_status: str | None = None
    profile_group: ObjectReference | None = None
    direct_profile_references: tuple[ObjectReference, ...] = ()
    utm_profile_references: tuple[ObjectReference, ...] = ()
    internet_service: bool | None = None
    internet_service_names: tuple[ObjectReference, ...] = ()
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    defaulted_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN

    @property
    def id(self) -> str:
        return self.policy_id


class PortRange(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    start: int = Field(ge=0, le=65535)
    end: int = Field(ge=0, le=65535)

    @model_validator(mode="after")
    def ordered(self) -> "PortRange":
        if self.end < self.start:
            raise ValueError("port range end must be greater than or equal to start")
        return self


class ServiceObject(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    tcp_port_ranges: tuple[PortRange, ...] = ()
    udp_port_ranges: tuple[PortRange, ...] = ()
    members: tuple[ObjectReference, ...] = ()
    service_type: str = "custom"
    protocol: str | None = None
    protocol_number: int | None = Field(default=None, ge=0, le=255)
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class VipGroup(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    members: tuple[ObjectReference, ...] = ()
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class RealServer(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    ip: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class Vip(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    extintf: tuple[str, ...] = ()
    extip: str | None = None
    mappedip: tuple[str, ...] = ()
    vip_type: str | None = None
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class VirtualServer(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    extintf: tuple[str, ...] = ()
    realservers: tuple[RealServer, ...] = ()
    vip_type: str | None = "server-load-balance"
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class ProfileGroup(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    profile_references: tuple[ObjectReference, ...] = ()
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class LogSetting(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    implicit_deny_log: str | None = None
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class Administrator(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    two_factor: str | None = None
    peer_auth: bool | None = None
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    defaulted_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class LocalUser(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    type: str | None = None
    two_factor: str | None = None
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    defaulted_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class SecurityProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    profile_type: str | None = None
    settings: tuple[ObjectReference, ...] = ()
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class UtmCategoryRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    categories: tuple[int, ...] = ()
    action: str | None = None
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    invalidated_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class UtmProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    profile_type: str
    external_blocklist_all: bool | None = None
    blocklist_enabled: bool | None = None
    error_allow: bool | None = None
    external_blocklists: tuple[str, ...] = ()
    external_ip_blocklists: tuple[str, ...] = ()
    analytics_db_enabled: bool | None = None
    block_malicious_url_enabled: bool | None = None
    scan_botnet_connections: str | None = None
    category_rules: tuple[UtmCategoryRule, ...] = ()
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    invalidated_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class SslVpnSettings(BaseModel):
    """Typed projection of the singleton ``config vpn ssl settings`` block."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: str | None = None
    source_interfaces: tuple[str, ...] = ()
    source_addresses: tuple[str, ...] = ()
    default_portal: str | None = None
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    defaulted_keys: frozenset[str] = Field(default_factory=frozenset)
    invalidated_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class IpsecPhase1(BaseModel):
    """Typed projection of one ``vpn ipsec phase1-interface`` entry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    status: str | None = None
    interface: str | None = None
    ike_version: int | None = None
    proposals: tuple[str, ...] = ()
    dh_groups: tuple[int, ...] = ()
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    defaulted_keys: frozenset[str] = Field(default_factory=frozenset)
    invalidated_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class IpsecPhase2(BaseModel):
    """Typed projection of one ``vpn ipsec phase2-interface`` entry."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    name: str
    status: str | None = None
    phase1_name: str | None = Field(
        default=None,
        validation_alias=AliasChoices("phase1_name", "phase1name"),
    )
    phase1_reference: ObjectReference | None = None
    pfs: str | None = None
    proposals: tuple[str, ...] = ()
    dh_groups: tuple[int, ...] = ()
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    defaulted_keys: frozenset[str] = Field(default_factory=frozenset)
    invalidated_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN

    @property
    def phase1name(self) -> str | None:
        """Compatibility spelling for the FortiOS directive name."""
        return self.phase1_name


class FortiGateConfiguration(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    hostname: str | None = None
    complete_backup: bool = False
    device_identity: DeviceIdentity = Field(default_factory=DeviceIdentity)
    interfaces: tuple[Interface, ...] = ()
    zones: tuple[Zone, ...] = ()
    policies: tuple[Policy, ...] = ()
    service_objects: tuple[ServiceObject, ...] = ()
    service_groups: tuple[ServiceObject, ...] = ()
    vips: tuple[Vip, ...] = ()
    vip_groups: tuple[VipGroup, ...] = ()
    virtual_servers: tuple[VirtualServer, ...] = ()
    profile_groups: tuple[ProfileGroup, ...] = ()
    log_setting: LogSetting | None = None
    implicit_deny_log: str | None = None
    object_references: tuple[ObjectReference, ...] = ()
    administrators: tuple[Administrator, ...] = ()
    local_users: tuple[LocalUser, ...] = ()
    security_profiles: tuple[SecurityProfile, ...] = ()
    utm_profiles: tuple[UtmProfile, ...] = ()
    ssl_vpn_settings: SslVpnSettings | None = None
    ipsec_phase1: tuple[IpsecPhase1, ...] = ()
    ipsec_phase2: tuple[IpsecPhase2, ...] = ()
    document: StructuralDocument = Field(default_factory=StructuralDocument)
    parsed_sections: frozenset[str] = Field(default_factory=frozenset)
    parsed_entry_sections: frozenset[str] = Field(default_factory=frozenset)
    parsed_value_sections: frozenset[str] = Field(default_factory=frozenset)


class AuditFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    control_id: str
    title: str
    status: AuditStatus
    category: str = "general"
    priority: AuditPriority = AuditPriority.P2
    severity: AuditSeverity = AuditSeverity.MEDIUM
    applicability: Applicability = Applicability.UNKNOWN
    evidence: tuple[str | EvidenceItem, ...] = ()
    evidence_items: tuple[EvidenceItem, ...] = ()
    affected_objects: tuple[AffectedObject, ...] = ()
    message: str
    risk: RiskAssessment | None = None
    recommendation: str | None = None
    remediation: str | None = None
    customer_approval: bool | None = None

    @field_validator("affected_objects", mode="before")
    @classmethod
    def normalize_affected_objects(cls, value: Any) -> Any:
        if value is None:
            return ()
        return tuple(
            item
            if isinstance(item, AffectedObject | dict)
            else AffectedObject(name=str(item))
            for item in value
        )

    @field_validator("risk", mode="before")
    @classmethod
    def normalize_risk(cls, value: Any) -> Any:
        if isinstance(value, str):
            return RiskAssessment(summary=value)
        return value

    @model_validator(mode="before")
    @classmethod
    def canonicalize_not_applicable(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        applicability = value.get("applicability")
        applicability_is_not_applicable = applicability in {
            Applicability.NOT_APPLICABLE,
            Applicability.NOT_APPLICABLE.value,
        }
        status = value.get("status")
        if applicability_is_not_applicable and status in {
            AuditStatus.FAIL,
            AuditStatus.FAIL.value,
            AuditStatus.ERROR,
            AuditStatus.ERROR.value,
        }:
            raise ValueError("FAIL or ERROR cannot be marked not applicable")
        status_is_not_applicable = status in {
            AuditStatus.NOT_APPLICABLE,
            AuditStatus.NOT_APPLICABLE.value,
        }
        if not applicability_is_not_applicable and not status_is_not_applicable:
            return value
        canonical = dict(value)
        canonical["status"] = AuditStatus.NOT_APPLICABLE
        canonical["applicability"] = Applicability.NOT_APPLICABLE
        return canonical

    @property
    def structured_evidence(self) -> tuple[EvidenceItem, ...]:
        return self.evidence_items
