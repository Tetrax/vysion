from datetime import date, datetime
from enum import StrEnum
from typing import Any

from pydantic import (
    AliasChoices,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)


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


class WanSelectionKind(StrEnum):
    INTERFACE = "interface"
    ZONE = "zone"
    SDWAN = "sdwan"
    AUTOMATIC = "automatic"


class WanSelection(BaseModel):
    """A typed WAN scope selected by the operator.

    ``interfaces`` is the server-resolved relation and is never trusted from
    the browser.  Keeping the selected scope and its expansion together lets
    controls preserve Interface → Zone → Flow → Policy provenance.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    kind: WanSelectionKind
    interfaces: tuple[str, ...] = ()
    automatic: bool = False

    @model_validator(mode="before")
    @classmethod
    def canonicalize_automatic(cls, data: Any) -> Any:
        if isinstance(data, dict):
            kind = data.get("kind")
            if kind in {WanSelectionKind.AUTOMATIC, WanSelectionKind.AUTOMATIC.value}:
                data = dict(data)
                data["automatic"] = True
        return data


class UtmLicenseStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"


def _coerce_legacy_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    return None


class UtmLicenseDetails(BaseModel):
    """Business-facing UTM license facts, separate from legacy boolean input."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    status: UtmLicenseStatus | None = None
    expiration_date: date | None = Field(
        default=None,
        validation_alias=AliasChoices("expiration_date", "expires_at"),
    )
    provenance: str | None = None
    manual: bool = False


class RuleMatchStatistics(BaseModel):
    """Optional runtime/operator observation, never configuration proof."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    unmatched_rules: int = Field(ge=0)
    total_rules: int | None = Field(default=None, ge=0)
    source: str = "operator"
    method: str = "Firewall policy Hit Count <= 0"

    @model_validator(mode="after")
    def validate_bounds(self) -> "RuleMatchStatistics":
        if self.total_rules is not None and self.unmatched_rules > self.total_rules:
            raise ValueError("unmatched_rules cannot exceed total_rules")
        if not self.source.strip() or not self.method.strip():
            raise ValueError("source and method must be non-empty")
        return self


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


class LegacyV1AdminPolicy(BaseModel):
    """Operator-supplied targets for the historical V1 administration rules."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    local_admin_names: tuple[str, ...]
    local_admin_mfa_email: str
    pki_peer_group: str
    deprecated_pki_account: str
    required_pki_account: str
    administration_fqdn: str
    dns_database_entry: str

    @model_validator(mode="after")
    def require_non_empty_targets(self) -> "LegacyV1AdminPolicy":
        values = (
            *self.local_admin_names,
            self.local_admin_mfa_email,
            self.pki_peer_group,
            self.deprecated_pki_account,
            self.required_pki_account,
            self.administration_fqdn,
            self.dns_database_entry,
        )
        if not self.local_admin_names or any(not value.strip() for value in values):
            raise ValueError("legacy_v1 administration targets must be non-empty")
        return self


class LegacyV1Rfc6890Policy(BaseModel):
    """Operator-supplied object aliases used by the historical blackhole rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    destination_objects: tuple[str, ...]

    @model_validator(mode="after")
    def require_destination_objects(self) -> "LegacyV1Rfc6890Policy":
        if not self.destination_objects or any(
            not value.strip() for value in self.destination_objects
        ):
            raise ValueError("legacy_v1 RFC6890 destinations must be non-empty")
        return self


class AuditContext(BaseModel):
    """Immutable operator/context facts; omitted booleans remain unknown (None)."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    selected_wans: tuple[str, ...] | None = None
    wan_selections: tuple[WanSelection, ...] | None = None
    operator_provenance: ContextProvenance | None = None
    client: str | None = Field(default=None, validation_alias=AliasChoices("client", "client_name"))
    site: str | None = Field(default=None, validation_alias=AliasChoices("site", "site_name"))
    serial_number: str | None = None
    uptime: str | None = None
    operator_comment: str | None = Field(
        default=None,
        validation_alias=AliasChoices("operator_comment", "comment", "context_comment"),
    )
    rule_match_statistics: RuleMatchStatistics | None = None
    schedule_reference_instant: AwareDatetime | None = None
    operator: str | None = Field(
        default=None,
        validation_alias=AliasChoices("operator", "network_operator", "operator_name"),
    )
    ha: bool | None = Field(default=None, validation_alias=AliasChoices("ha", "ha_enabled"))
    ha_cabling_redundancy: bool | None = None
    mpls: bool | None = Field(default=None, validation_alias=AliasChoices("mpls", "mpls_enabled"))
    utm_license: bool | None = Field(
        default=None,
        validation_alias=AliasChoices("utm_license", "utm_licensed"),
    )
    utm_license_details: UtmLicenseDetails | None = None
    utm_license_details_explicit: bool = Field(default=False, exclude=True)
    psirt: PsirtObservation | None = None
    legacy_v1_admin_policy: LegacyV1AdminPolicy | None = None
    legacy_v1_rfc6890_policy: LegacyV1Rfc6890Policy | None = None

    @model_validator(mode="before")
    @classmethod
    def canonicalize_business_context(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        canonical = dict(value)
        selections = canonical.get("wan_selections")
        if selections is not None:
            derived_selected_wans = tuple(
                item.get("name") if isinstance(item, dict) else item.name
                for item in selections
            )
            selected_wans = canonical.get("selected_wans")
            if selected_wans is not None:
                declared_selected_wans = (
                    (selected_wans,) if isinstance(selected_wans, str) else selected_wans
                )
                declared_names = sorted(
                    str(item).strip().casefold() for item in declared_selected_wans
                )
                derived_names = sorted(
                    str(item).strip().casefold() for item in derived_selected_wans
                )
                if declared_names != derived_names:
                    raise ValueError(
                        "selected_wans conflicts with wan_selections"
                    )
            else:
                canonical["selected_wans"] = derived_selected_wans

        details = canonical.get("utm_license_details")
        canonical["utm_license_details_explicit"] = details is not None
        legacy_license = canonical.get("utm_license", canonical.get("utm_licensed"))
        if details is None and legacy_license is not None:
            active = _coerce_legacy_bool(legacy_license)
            if active is not None:
                canonical["utm_license_details"] = {
                    "status": UtmLicenseStatus.ACTIVE if active else UtmLicenseStatus.INACTIVE,
                    "manual": True,
                }
        elif details is not None and legacy_license is None:
            status = (
                details.get("status")
                if isinstance(details, dict)
                else getattr(details, "status", None)
            )
            if status is not None:
                normalized = status.value if isinstance(status, UtmLicenseStatus) else str(status)
                canonical["utm_license"] = normalized.casefold() == UtmLicenseStatus.ACTIVE.value
        elif details is not None and legacy_license is not None:
            status = (
                details.get("status")
                if isinstance(details, dict)
                else getattr(details, "status", None)
            )
            active = _coerce_legacy_bool(legacy_license)
            if status is None and active is not None:
                normalized_details = (
                    dict(details)
                    if isinstance(details, dict)
                    else details.model_dump(mode="python")
                )
                normalized_details["status"] = (
                    UtmLicenseStatus.ACTIVE if active else UtmLicenseStatus.INACTIVE
                )
                canonical["utm_license_details"] = normalized_details
        return canonical

    @model_validator(mode="after")
    def validate_utm_license_consistency(self) -> "AuditContext":
        if self.utm_license is not None and self.utm_license_details is not None:
            status = self.utm_license_details.status
            if status is not None and self.utm_license != (
                status is UtmLicenseStatus.ACTIVE
            ):
                raise ValueError("utm_license conflicts with utm_license_details.status")
        return self

    @model_serializer(mode="wrap")
    def serialize_business_context(self, handler: Any) -> dict[str, Any]:
        serialized = handler(self)
        if not self.utm_license_details_explicit:
            serialized.pop("utm_license_details", None)
        for field_name in (
            "wan_selections",
            "serial_number",
            "uptime",
            "rule_match_statistics",
            "schedule_reference_instant",
            "operator",
            "ha_cabling_redundancy",
            "legacy_v1_admin_policy",
            "legacy_v1_rfc6890_policy",
        ):
            if getattr(self, field_name) is None:
                serialized.pop(field_name, None)
        return serialized

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
    interface_type: str | None = None
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


class OnetimeSchedule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    end: datetime | None = None
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class RecurringSchedule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    proof_state: ProofState = ProofState.UNKNOWN


class ScheduleGroup(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    members: tuple[ObjectReference, ...] = ()
    proof_state: ProofState = ProofState.UNKNOWN


class ScheduleCounts(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    always: int = Field(ge=0)
    active: int = Field(ge=0)
    expired: int = Field(ge=0)


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


class AddressObject(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    address_type: str | None = None
    fqdn: str | None = None
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class AddressGroup(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    members: tuple[ObjectReference, ...] = ()
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class StaticRoute(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    route_id: str
    destination: ObjectReference | None = None
    blackhole: bool | None = None
    distance: int | None = Field(default=None, ge=0, le=255)
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    invalidated_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class DnsDatabaseEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
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


class HaSettings(BaseModel):
    """Typed singleton projection of ``config system ha``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    group_name: str | None = None
    session_pickup: str | None = None
    session_pickup_connectionless: str | None = None
    session_pickup_expectation: str | None = None
    heartbeat_interfaces: tuple[str, ...] = ()
    override: str | None = None
    override_wait_time: int | None = None
    parsed_keys: frozenset[str] = Field(default_factory=frozenset)
    invalidated_keys: frozenset[str] = Field(default_factory=frozenset)
    proof_state: ProofState = ProofState.UNKNOWN


class FortiGateConfiguration(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    hostname: str | None = None
    complete_backup: bool = False
    device_identity: DeviceIdentity = Field(default_factory=DeviceIdentity)
    interfaces: tuple[Interface, ...] = ()
    zones: tuple[Zone, ...] = ()
    sdwan_zones: tuple[Zone, ...] = ()
    policies: tuple[Policy, ...] = ()
    onetime_schedules: tuple[OnetimeSchedule, ...] = ()
    recurring_schedules: tuple[RecurringSchedule, ...] = ()
    schedule_groups: tuple[ScheduleGroup, ...] = ()
    service_objects: tuple[ServiceObject, ...] = ()
    service_groups: tuple[ServiceObject, ...] = ()
    vips: tuple[Vip, ...] = ()
    vip_groups: tuple[VipGroup, ...] = ()
    address_objects: tuple[AddressObject, ...] = ()
    address_groups: tuple[AddressGroup, ...] = ()
    dns_database_entries: tuple[DnsDatabaseEntry, ...] = ()
    static_routes: tuple[StaticRoute, ...] = ()
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
    ha_settings: HaSettings | None = None
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
    rule_provenance: str | None = None
    schedule_counts: ScheduleCounts | None = None

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
