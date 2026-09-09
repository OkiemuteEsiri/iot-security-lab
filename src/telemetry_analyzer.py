from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class TelemetryFinding:
    rule_id: str
    severity: str
    device_id: str
    title: str
    evidence: str
    attack_context: tuple[str, ...]
    remediation: str
    validation: str


def load_events(path: str | Path) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("Expected a JSON list of telemetry events")
    return data


def analyze_telemetry(events: list[dict[str, Any]]) -> list[TelemetryFinding]:
    findings: list[TelemetryFinding] = []
    auth_failures = Counter()

    for event in events:
        device_id = str(event.get("device_id", "unknown"))
        event_type = str(event.get("event_type", "")).lower()

        if event_type == "network_connection":
            destination = str(event.get("destination", "unknown"))
            destination_approved = bool(event.get("destination_approved", True))
            protocol = str(event.get("protocol", "unknown")).lower()
            port = int(event.get("port", 0) or 0)

            if not destination_approved:
                findings.append(TelemetryFinding(
                    "IOT-T001", "high", device_id,
                    "Connection to unapproved destination",
                    f"Observed {protocol} connection to unapproved destination {destination}:{port}.",
                    ("T1071",),
                    "Restrict device egress to approved services and investigate whether the destination is operationally required.",
                    "Confirm the destination is blocked or formally approved, then review subsequent telemetry for recurrence."
                ))

            if protocol == "mqtt" and port == 1883:
                findings.append(TelemetryFinding(
                    "IOT-T002", "high", device_id,
                    "Plaintext MQTT transport",
                    "MQTT traffic was observed over TCP/1883 rather than an approved encrypted transport.",
                    ("T1071",),
                    "Migrate telemetry to TLS-protected MQTT and enforce certificate validation on clients and brokers.",
                    "Confirm broker/client configuration uses encrypted transport and verify no further TCP/1883 events are present."
                ))

        elif event_type == "publish_rate":
            observed = float(event.get("messages_per_minute", 0) or 0)
            baseline = float(event.get("baseline_messages_per_minute", 0) or 0)
            if baseline > 0 and observed >= baseline * 5:
                findings.append(TelemetryFinding(
                    "IOT-T003", "medium", device_id,
                    "Telemetry publish-rate anomaly",
                    f"Observed {observed:.0f} messages/minute against baseline {baseline:.0f}.",
                    ("T1071",),
                    "Validate the device workload and rate-limit unexpected telemetry bursts at the device, broker, or gateway tier.",
                    "Confirm publish rate returns to the approved operating range and document any approved baseline change."
                ))

        elif event_type == "authentication":
            if str(event.get("result", "")).lower() == "failure":
                auth_failures[device_id] += 1

        elif event_type == "broker_registration":
            if not bool(event.get("broker_approved", True)):
                broker = str(event.get("broker", "unknown"))
                findings.append(TelemetryFinding(
                    "IOT-T005", "critical", device_id,
                    "Unapproved message broker registration",
                    f"Device registered with unapproved broker {broker}.",
                    ("T1071", "T1021"),
                    "Remove unauthorized broker trust, restrict broker allowlists, and review device configuration provenance.",
                    "Confirm the device can register only with approved brokers and validate trust-store/configuration integrity."
                ))

    for device_id, count in auth_failures.items():
        if count >= 5:
            findings.append(TelemetryFinding(
                "IOT-T004", "high", device_id,
                "Repeated authentication failures",
                f"Observed {count} authentication failures in the supplied telemetry window.",
                ("T1078",),
                "Review identity configuration, rotate affected credentials through approved processes, and enforce throttling or lockout safeguards where supported.",
                "Confirm expected identity use and verify failure volume returns below the documented threshold."
            ))

    return sorted(findings, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True)


def summarize(findings: list[TelemetryFinding]) -> dict[str, int]:
    summary = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        summary[finding.severity] += 1
    return summary


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python src/telemetry_analyzer.py data/telemetry.json")
        return 2
    findings = analyze_telemetry(load_events(sys.argv[1]))
    payload = {"summary": summarize(findings), "findings": [asdict(item) for item in findings]}
    print(json.dumps(payload, indent=2))
    return 1 if any(item.severity in {"critical", "high"} for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
