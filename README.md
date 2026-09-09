# IoT Security Engineering Lab

A defensive IoT security project that models device-inventory review, firmware/configuration risk assessment, behavioral telemetry analysis, fleet-level risk prioritization, and remediation validation using synthetic device data.

## Problem statement

IoT programs often combine weak asset visibility, long-lived firmware, insecure management protocols, default-account risk, flat network placement, limited patching capability, and poorly governed telemetry paths. A mature security review therefore needs both **static posture checks** and **runtime behavioral evidence** rather than relying on one data source.

This repository demonstrates how a security engineer can convert those conditions into repeatable controls, explainable detections, prioritized findings, and measurable revalidation steps without probing live devices.

## Architecture

```text
synthetic device inventory ------------------+
        |                                     |
        v                                     |
static posture controls                       |
firmware / protocols / identity               |
segmentation / encryption / updates           |
        |                                     |
        +-------------------+                 |
                            v                 v
                     fleet risk aggregation + metrics
                            ^                 ^
                            |                 |
synthetic telemetry --------+-----------------+
        |
        v
behavioral telemetry controls
egress / broker trust / auth failures
plaintext MQTT / publish-rate anomalies
        |
        v
findings + evidence + remediation + validation
```

See [`docs/architecture.md`](docs/architecture.md) for the detailed component and trust-boundary model.

## Static posture controls

| Control | Purpose | Example risk |
|---|---|---|
| IOT-001 | Unsupported/outdated firmware | High |
| IOT-002 | Insecure management protocol | Critical |
| IOT-003 | Default/shared credential indicator | Critical |
| IOT-004 | Missing network segmentation | High |
| IOT-005 | Unencrypted telemetry | High |
| IOT-006 | Automatic update disabled | Medium |

## Behavioral telemetry controls

| Rule | Purpose | Severity |
|---|---|---:|
| IOT-T001 | Detect connection to unapproved destination | High |
| IOT-T002 | Detect MQTT over plaintext TCP/1883 | High |
| IOT-T003 | Detect publish rate >= 5x approved baseline | Medium |
| IOT-T004 | Detect repeated authentication failures | High |
| IOT-T005 | Detect registration with an unapproved broker | Critical |

## Repository structure

```text
src/iot_analyzer.py             static security posture engine
src/telemetry_analyzer.py       behavioral telemetry detection engine
src/fleet_metrics.py            fleet-level aggregation and prioritization
data/devices.json               synthetic IoT inventory
data/telemetry.json             synthetic normalized telemetry

tests/test_iot_analyzer.py      posture unit tests
tests/test_telemetry_analyzer.py telemetry rule unit tests
tests/test_fleet_metrics.py     fleet metrics unit tests

docs/architecture.md            technical architecture and trust boundaries
docs/methodology.md             assessment methodology
docs/threat-model.md            defensive threat model
docs/remediation-validation.md  closure workflow

reports/example-report.md       static posture example
reports/telemetry-example.md    telemetry assessment example
.github/workflows/ci.yml        GitHub Actions test workflow
```

## Usage

Run all tests:

```bash
python -m unittest discover -s tests -v
```

Run the static posture assessment:

```bash
python src/iot_analyzer.py data/devices.json
```

Run the telemetry assessment:

```bash
python src/telemetry_analyzer.py data/telemetry.json
```

Both analyzers return a non-zero exit code when high or critical findings are present, which makes them suitable for controlled validation or CI demonstrations. No external Python dependencies are required.

## Methodology

1. Normalize asset and telemetry evidence.
2. Evaluate deterministic static controls.
3. Evaluate explainable telemetry rules.
4. Aggregate severity and affected-device metrics.
5. Prioritize remediation based on evidence rather than scanner volume alone.
6. Re-run the relevant control after remediation and retain validation evidence.

The full methodology is documented in [`docs/methodology.md`](docs/methodology.md).

## MITRE ATT&CK context

Relevant contextual mappings include:

- **T1071 — Application Layer Protocol** for weakly governed or unexpected protocol destinations.
- **T1078 — Valid Accounts** for authentication-abuse context.
- **T1021 — Remote Services** for remotely reachable service/broker trust relationships.

Mappings are defensive context only. A matched rule does **not** establish that an adversary technique occurred.

## Remediation and validation workflow

Every finding carries both a recommended action and a closure test. The intended workflow is:

```text
finding -> owner -> approved change -> evidence collection -> rule re-run -> validated closure
```

Exceptions should be time-bounded, assigned to an accountable owner, and supported by compensating controls.

## Skills demonstrated

- IoT security architecture review
- Asset and firmware risk management
- Secure protocol assessment
- Network segmentation analysis
- MQTT security posture
- Behavioral detection engineering
- Identity and broker-trust review
- Python security automation
- Fleet-level risk aggregation
- Remediation validation
- Unit testing and CI
- ATT&CK-informed defensive analysis

## Design decisions

- **Synthetic evidence only:** prevents accidental disclosure of client or employer information.
- **No active scanning:** keeps the project defensive and safe to run.
- **Deterministic rules:** makes tests and revalidation reproducible.
- **Evidence-first findings:** supports analyst review instead of opaque scoring.
- **Separate posture and telemetry engines:** avoids conflating a weak configuration with observed malicious behavior.

## Limitations

This lab does not scan, exploit, authenticate to, or reconfigure real devices. Synthetic metadata cannot reproduce every embedded OS, protocol, safety constraint, or vendor lifecycle. Production validation would require explicit authorization plus authenticated inventory/configuration exports, vendor lifecycle evidence, network or broker telemetry, certificate data, CMDB ownership, and change-management records.

The fleet risk score is a triage indicator, not a probability of compromise or breach.

## Roadmap

- Add vendor lifecycle enrichment interface
- Add certificate-expiry and TLS-profile checks
- Add SBOM/firmware component intake format
- Add exception governance with expiry dates
- Add broker policy and topic-ACL validation
- Add fleet trend snapshots across assessment periods
- Add machine-readable SARIF/JSON report export

## Ethical scope

Use only with assets and data you own or are explicitly authorized to assess. No employer, client, production data, credentials, exploit payloads, or live targeting are included.
