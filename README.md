# IoT Security Engineering Lab

A defensive IoT security project that models device-inventory review, firmware/configuration risk assessment, protocol exposure analysis, identity/credential hygiene, and remediation validation using synthetic device data.

## Objective

IoT programs often combine weak asset visibility, long-lived firmware, insecure management protocols, default-account risk, flat network placement, and limited patching capability. This repository demonstrates how a security engineer can convert those conditions into repeatable controls and prioritized findings.

## Architecture

```text
synthetic IoT inventory
        |
        v
normalization + control checks
        |
        +--> firmware age/support
        +--> insecure protocols
        +--> default/shared credential flags
        +--> segmentation posture
        +--> encryption and update controls
        |
        v
severity + remediation guidance
        |
        v
revalidation evidence
```

## Controls

| Control | Purpose | Example risk |
|---|---|---|
| IOT-001 | Unsupported/outdated firmware | High |
| IOT-002 | Insecure management protocol | Critical |
| IOT-003 | Default/shared credential indicator | Critical |
| IOT-004 | Missing network segmentation | High |
| IOT-005 | Unencrypted telemetry | High |
| IOT-006 | Automatic update disabled | Medium |

## Repository structure

```text
src/iot_analyzer.py             security posture engine
data/devices.json               synthetic IoT inventory
tests/test_iot_analyzer.py      unit tests
docs/threat-model.md            defensive threat model
docs/remediation-validation.md  closure workflow
reports/example-report.md       example findings
.github/workflows/ci.yml        GitHub Actions tests
```

## Run

```bash
python -m unittest discover -s tests -v
python src/iot_analyzer.py data/devices.json
```

No external Python dependencies are required.

## Threat context

The project maps weaknesses to defensive concerns such as initial access through exposed management services, credential abuse, lateral movement from poorly segmented devices, and command-and-control opportunities through unencrypted or unmanaged channels. ATT&CK references are contextual only; offensive procedures are intentionally excluded.

## Skills demonstrated

- IoT security architecture review
- Asset and firmware risk management
- Protocol hardening
- Segmentation assessment
- Python security automation
- Risk prioritization
- Remediation validation
- Unit testing and CI

## Limitations

This lab does not scan real devices or perform exploitation. Synthetic metadata is used to demonstrate security-engineering logic. Production validation would require authorized device inventories, vendor lifecycle data, network telemetry, configuration exports, and change-management records.

## Roadmap

- Add vendor lifecycle enrichment interface
- Add certificate-expiry and TLS-profile checks
- Add SBOM/firmware component intake format
- Add exception governance with expiry dates
- Add fleet-level trend metrics

## Ethical scope

Use only with assets and data you own or are explicitly authorized to assess. No employer, client, or production data is included.