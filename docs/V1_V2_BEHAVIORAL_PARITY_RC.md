# V1/V2 behavioral parity release candidate

Date: 2026-08-19
Branch: `feat/v1-behavioral-parity`
Protected baseline: `main@23e219b11a18bcc6d5ff90799f3cdd6739883953` (Vysion 2.3.5)

## Architecture boundary

The V1 monolith remains an isolated Python 3.12 comparison oracle. It is not copied into the V2 package, image, or runtime. V2 keeps the structural parser, typed projections, `AuditContext`, `AuditFinding`, registry, canonical JSON, and existing renderers.

## Capability matrix

`docs/V1_V2_CAPABILITY_MAP.json` and `docs/V1_V2_DETERMINISTIC_PARITY_MATRIX.md` are the canonical exhaustive maps. The runtime presentation layer consumes the same JSON map:

- 59 V1 business capabilities inventoried one by one;
- 57 included V1 points presented with historical client labels;
- 53 registered V1 capabilities produce 56 internal V2 findings;
- 2 V1 capabilities are split into multiple V2 sub-checks, adding 3 internal rows;
- 4 V2-only controls are presented separately;
- 2 V1 typed implementations remain outside the engine registry and 2 capabilities are data projections;
- 1 external-source capability classified `BLOCKED_EXTERNAL_SOURCE` (FortiGate EOL);
- 1 runtime-data capability classified `BLOCKED_RUNTIME_DATA` (FortiGate hit counts);
- 0 `UNRESOLVED_DIVERGENCE` outside those two exclusions;
- PSIRT/FortiGuard live observations are explicitly outside the parity gate and remain fail-closed.

CTI and ISDB retain their existing typed V2 implementations and are classified in the matrix without adding findings to the 60-control release registry. Projection-only V1 capabilities are evaluated from typed configuration data rather than counted as additional controls.

## Differential replay

The reproducible runner is:

```bash
.venv/bin/python tools/parity/run_differential.py \
  --output docs/V1_V2_SYNTHETIC_PARITY_REPORT.json
```

The synthetic corpus contains 10 deterministic positive/negative cases across guest/default accounts, VIP, virtual server, and SSL-VPN behavior. Result:

- 9 exact status matches;
- 1 explicit semantic equivalence (`PASS -> NOT_APPLICABLE` for disabled SSL-VPN);
- 0 unresolved divergences.

The real reference was replayed temporarily with redacted output outside Git. Result:

- 33 active interfaces after excluding explicit `set status down`, matching V1 and removing the former `modem` projection divergence;
- 5 exact status matches across 7 replayed controls;
- 2 explicit semantic equivalences: absent VIP namespace and disabled SSL-VPN are `PASS` in V1 and `NOT_APPLICABLE` in V2;
- 0 unresolved divergences in the bounded real-reference subset;
- no client configuration, message, evidence, object, or generated real report persisted in Git.

Semantic equivalence is reported separately and never counted as an exact match. V2 retains `NOT_APPLICABLE` where the control is conditionally irrelevant instead of fabricating a `PASS`.

## Corrections included

- Explicitly down interfaces are excluded from the active interface projection while remaining available in the structural document.
- Guest-account detection follows V1's `config user local` scope and reports proven absence as `PASS`.
- The existing object control now evaluates V1 object families through the structural document and typed references, while preserving UNKNOWN for incomplete exports and service mutations/collisions.
- Differential summaries separate exact matches, semantic equivalences, and unresolved divergences.
- Real-reference output is redacted and stores only aggregate projection counts.

## Existing regression coverage used for priority semantics

The full suite covers the already implemented V2 parity behavior for Geo-IP, LDAP/SSL-VPN absence, ALL service, sensitive ports, HA, UTM, VPN, administration, unused objects, and schedules. The new differential corpus is a bounded executable comparison layer; it does not claim that all 59 V1 capabilities were dynamically replayed in one run.

## External and runtime contracts

- **EOL:** remains `BLOCKED_EXTERNAL_SOURCE`. `EXT-PSIRT-001` is not treated as an EOL substitute. No EOL status is fabricated without a reliable, versioned source.
- **Hit counts:** remains `BLOCKED_RUNTIME_DATA`. `RuleMatchStatistics` is accepted only as optional observed runtime context; counts are never inferred from a configuration backup.
- **Unavailable proof:** remains `UNKNOWN` where applicable. It is not converted into `PASS`.

## Verification

- Backend: `814 passed`.
- Differential tests: `13 passed` (included in backend total).
- Parity matrix gate: 59 rows, 57 included V1 presentation points, 2 explicit exclusions, 0 unresolved outside exclusions.
- Presentation contract: 57 business points, 60 engine controls, 3 split sub-checks, 4 V2-only controls separated.
- SD-WAN presentation: all declared zones, observed members, zone-to-member relations and proof state are exposed in preview.
- Client labels: `display_name` is populated from the V1 presentation map; internal `control_id` remains machine-only.
- DOCX V1 restoration: numbered client order, V1 template/header/footer/confidentiality, logo placeholder/optional logo insertion, VPN SSL N/A, HA/CTI/ISDB/UTM diagrams.
- XLSX: client labels plus the `Matrice V1-V2` sheet are generated from the same presentation contract.
- Frontend: 3 files / 12 tests passed.
- Frontend ESLint and TypeScript/Vite build: passed on the protected GUI snapshot.
- Compose validation: passed on the protected delivery path.

## Release boundary and remaining limits

This branch is a release candidate only. No production image was replaced and no deployment was performed. A separate human authorization is required before merge/release/deployment.

Remaining limits are explicit: the dynamic corpus is representative rather than exhaustive across all 59 capabilities; FortiGate EOL requires a versioned external source; policy hit counts require observed runtime data; broader multi-configuration field validation remains necessary before claiming universal behavioral identity.
