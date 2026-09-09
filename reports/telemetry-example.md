# Example IoT Telemetry Assessment

> Synthetic example only. No production devices, credentials, or client data are represented.

## Executive summary

The supplied telemetry window contains multiple conditions that warrant defensive review: one device communicates with an unapproved destination over plaintext MQTT, another shows a material publish-rate deviation from its baseline, and a gateway attempts to register with an unapproved broker. Repeated authentication failures are also present for one camera.

The highest-priority condition is the unapproved broker registration because it changes the device's trusted messaging path. The next priority is the combination of unapproved egress and plaintext MQTT, which increases exposure of device telemetry and weakens network-control assumptions.

## Findings

| Rule | Device | Severity | Observation | Recommended action |
|---|---|---:|---|---|
| IOT-T005 | gateway-02 | Critical | Registration with `broker-shadow.lab.local` | Remove unauthorized broker trust, enforce broker allowlist, validate configuration provenance |
| IOT-T001 | camera-02 | High | Connection to unapproved destination `203.0.113.55` | Restrict egress and validate business requirement |
| IOT-T002 | camera-02 | High | MQTT over TCP/1883 | Move to TLS-protected MQTT and validate certificate trust |
| IOT-T004 | camera-02 | High | Five authentication failures in the supplied window | Review identity configuration and apply approved credential remediation |
| IOT-T003 | sensor-04 | Medium | 360 messages/minute vs baseline 60 | Validate workload, investigate burst, and rate-limit if unauthorized |

## ATT&CK context

- **T1071 — Application Layer Protocol:** contextual reference for unexpected or weakly governed application-protocol use.
- **T1078 — Valid Accounts:** contextual reference for identity misuse concerns associated with repeated authentication failures.
- **T1021 — Remote Services:** contextual reference for trust relationships involving remotely reachable broker/service infrastructure.

These mappings are not assertions that an adversary technique occurred.

## Remediation sequence

1. Quarantine or logically restrict the unapproved broker relationship while preserving operational safety.
2. Block or formally approve the unexpected external destination.
3. Migrate plaintext MQTT to an approved encrypted transport.
4. Review the camera identity configuration and rotate credentials through an authorized process if compromise or misconfiguration is suspected.
5. Confirm the sensor publish-rate increase is expected; otherwise restore the approved baseline and investigate root cause.

## Validation criteria

- No device registers with an unapproved broker.
- No MQTT sessions are observed over TCP/1883.
- Egress destinations match the approved allowlist.
- Authentication failures remain below the documented threshold or have an explained operational cause.
- Publish-rate metrics remain within the approved baseline or a formally changed baseline.

## Residual risk

Even after these controls pass, residual risk remains around firmware provenance, physical access, device-specific vulnerabilities, certificate lifecycle, and management-plane exposure. Those areas require separate evidence sources and are outside this telemetry-only example.
