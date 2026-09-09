# Architecture

## Security engineering objective

The lab separates **configuration posture** from **behavioral telemetry** so that static weaknesses and runtime anomalies are assessed independently before being combined into fleet-level risk metrics.

```text
                  +----------------------+
                  | synthetic inventory  |
                  +----------+-----------+
                             |
                             v
                  +----------------------+
                  | posture analyzer     |
                  | firmware/protocols   |
                  | identity/segmentation|
                  +----------+-----------+
                             |
                             +------------------+
                                                |
+----------------------+                        v
| synthetic telemetry  |              +------------------+
+----------+-----------+              | fleet metrics    |
           |                          | severity counts  |
           v                          | affected devices |
+----------------------+              | priority signal  |
| telemetry analyzer   |--------------+------------------+
| egress/broker/auth   |
| publish-rate checks  |
+----------+-----------+
           |
           v
+----------------------+
| findings + evidence  |
| remediation          |
| validation steps     |
+----------------------+
```

## Components

### `src/iot_analyzer.py`
Evaluates device-level security posture using deterministic controls. It does not probe devices or perform network activity.

### `src/telemetry_analyzer.py`
Consumes normalized synthetic telemetry events and identifies explainable behavioral conditions such as unapproved destinations, plaintext MQTT, abnormal publish volume, repeated authentication failures, and unapproved broker registration.

### `src/fleet_metrics.py`
Aggregates findings into fleet-level metrics. The score is intentionally a relative triage indicator rather than a prediction of compromise.

## Trust boundaries

1. **Inventory boundary** — device metadata must be validated before assessment.
2. **Telemetry boundary** — event records are treated as observations, not proof of malicious activity.
3. **Policy boundary** — approved destinations, brokers, protocols, and baselines are governance inputs.
4. **Reporting boundary** — findings must preserve evidence and avoid overstating exploitability.

## Design properties

- No live scanning or exploitation.
- Deterministic controls suitable for unit testing.
- Evidence is retained in each finding.
- Remediation includes explicit validation criteria.
- ATT&CK mappings are contextual references, not claims that an adversary technique occurred.

## Production extension points

A production implementation could add vendor lifecycle feeds, authenticated configuration exports, certificate inventory, message-broker logs, network flow telemetry, CMDB ownership, exception records, and ticketing integration. Those integrations are intentionally excluded from the lab because they would require environment-specific authorization and credentials.
