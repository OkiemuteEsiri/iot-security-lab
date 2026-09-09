# Assessment Methodology

## Scope

This methodology evaluates synthetic IoT inventories and telemetry for security-engineering weaknesses without interacting with live devices.

## Phase 1 — Inventory normalization

Validate that each device has a stable identifier and sufficient metadata for firmware, protocol, credential, segmentation, encryption, and update-policy checks. Missing metadata should be treated as an evidence gap rather than silently assumed secure.

## Phase 2 — Static posture assessment

Run deterministic controls against the inventory:

- unsupported firmware lifecycle
- insecure management protocols
- default/shared credential indicators
- missing segmentation
- unencrypted telemetry
- absent automatic-update capability

Findings are prioritized by severity and include remediation plus a closure test.

## Phase 3 — Behavioral telemetry assessment

Evaluate normalized events for:

| Rule | Condition | Severity | ATT&CK context |
|---|---|---:|---|
| IOT-T001 | Connection to unapproved destination | High | T1071 |
| IOT-T002 | MQTT observed over TCP/1883 | High | T1071 |
| IOT-T003 | Publish rate >= 5x approved baseline | Medium | T1071 |
| IOT-T004 | >= 5 authentication failures in the supplied window | High | T1078 |
| IOT-T005 | Registration with unapproved broker | Critical | T1071, T1021 |

The ATT&CK references provide analyst context only. A matching condition does not prove compromise or adversary intent.

## Phase 4 — Fleet prioritization

Aggregate findings by severity and affected device. Fleet metrics are designed to answer operational questions:

- How much of the fleet is affected?
- Which devices concentrate the most findings?
- Are critical/high findings present?
- Does remediation require immediate, accelerated, or standard handling?

The normalized risk score is a triage aid, not a quantitative breach probability.

## Phase 5 — Remediation and validation

For each finding:

1. identify an accountable owner;
2. confirm business and safety constraints;
3. implement the least disruptive secure change;
4. collect configuration or telemetry evidence after change;
5. rerun the relevant control;
6. close only when the validation criterion is satisfied;
7. document time-bounded exceptions when remediation is not immediately feasible.

## Evidence quality

Recommended evidence hierarchy:

1. authenticated configuration/export from the device or management platform;
2. network or broker telemetry corroborating the configuration;
3. vendor lifecycle documentation;
4. CMDB/asset records;
5. manual attestations as a temporary fallback.

## Limitations

Synthetic data cannot reproduce every device protocol, embedded operating system, safety constraint, or vendor-specific lifecycle. Production assessments require authorization, change control, device-owner coordination, and validation that defensive changes do not disrupt operational technology or safety-critical functions.
