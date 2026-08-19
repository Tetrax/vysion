# V1/V2 behavioral parity release candidate

Date: 2026-08-19
Branch: `feat/v1-behavioral-parity`
Protected baseline: `main@23e219b11a18bcc6d5ff90799f3cdd6739883953` (Vysion 2.3.5)

## Architecture boundary

The V1 monolith remains an isolated Python 3.12 comparison oracle. It is not copied into the V2 package, image, or runtime. V2 keeps the structural parser, typed projections, `AuditContext`, `AuditFinding`, registry, canonical JSON, and existing renderers.

## Capability matrix

`docs/V1_V2_CAPABILITY_MAP.json` is the canonical exhaustive map:

- 59 V1 business capabilities inventoried;
- 53 V1 capabilities mapped to 56 registered V2 findings;
- 2 V1 capabilities represented as typed projections;
- 2 existing V2 implementations explicitly outside the registry (CTI and ISDB);
- 1 external-source capability blocked (FortiGate EOL);
- 1 runtime-data capability blocked (policy hit counts);
- 4 V2-only findings identified.

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
- Differential summaries separate exact matches, semantic equivalences, and unresolved divergences.
- Real-reference output is redacted and stores only aggregate projection counts.

## Existing regression coverage used for priority semantics

The full suite covers the already implemented V2 parity behavior for Geo-IP, LDAP/SSL-VPN absence, ALL service, sensitive ports, HA, UTM, VPN, administration, unused objects, and schedules. The new differential corpus is a bounded executable comparison layer; it does not claim that all 59 V1 capabilities were dynamically replayed in one run.

## External and runtime contracts

- **EOL:** remains `BLOCKED_EXTERNAL_SOURCE`. `EXT-PSIRT-001` is not treated as an EOL substitute. No EOL status is fabricated without a reliable, versioned source.
- **Hit counts:** remains `BLOCKED_RUNTIME_DATA`. `RuleMatchStatistics` is accepted only as optional observed runtime context; counts are never inferred from a configuration backup.
- **Unavailable proof:** remains `UNKNOWN` where applicable. It is not converted into `PASS`.

## Verification

- Backend: `802 passed`.
- Differential tests: `13 passed` (included in backend total).
- Ruff: all checks passed.
- Frontend: 3 files / 10 tests passed.
- Frontend ESLint: passed with project-local ESLint 9.34.0.
- Frontend TypeScript/Vite build: passed.
- Compose validation: passed.
- Production runtime after verification: `running|healthy|0`, image remains `vysion:23e219b11a18bcc6d5ff90799f3cdd6739883953`.
- Rollback tags remain present: `vysion:rollback-v2.3.3` and `vysion:rollback-v2.3.4`.

## Release boundary and remaining limits

This branch is a release candidate only. No production image was replaced and no deployment was performed. A separate human authorization is required before merge/release/deployment.

Remaining limits are explicit: the dynamic corpus is representative rather than exhaustive across all 59 capabilities; FortiGate EOL requires a versioned external source; policy hit counts require observed runtime data; broader multi-configuration field validation remains necessary before claiming universal behavioral identity.
