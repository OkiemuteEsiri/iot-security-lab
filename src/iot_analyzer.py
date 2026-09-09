from __future__ import annotations

import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
INSECURE_PROTOCOLS = {"telnet", "ftp", "http", "snmpv1", "snmpv2c"}


@dataclass(frozen=True)
class Finding:
    control_id: str
    severity: str
    device_id: str
    evidence: str
    remediation: str
    validation: str


def load_devices(path: str | Path) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("Expected a JSON list of devices")
    return data


def analyze(devices: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []

    for device in devices:
        device_id = str(device["device_id"])
        firmware_supported = bool(device.get("firmware_supported", True))
        protocols = {str(p).lower() for p in device.get("management_protocols", [])}
        default_credentials = bool(device.get("default_or_shared_credentials", False))
        segmented = bool(device.get("segmented", False))
        telemetry_encrypted = bool(device.get("telemetry_encrypted", True))
        auto_update = bool(device.get("automatic_updates", True))

        if not firmware_supported:
            findings.append(Finding(
                "IOT-001", "high", device_id,
                "Firmware is marked unsupported or outside the approved lifecycle.",
                "Upgrade to a vendor-supported release or replace the device under a documented lifecycle plan.",
                "Confirm supported firmware version and record vendor lifecycle evidence."
            ))

        insecure = sorted(protocols & INSECURE_PROTOCOLS)
        if insecure:
            findings.append(Finding(
                "IOT-002", "critical", device_id,
                f"Insecure management protocols enabled: {', '.join(insecure)}.",
                "Disable legacy services and use approved encrypted management protocols from restricted admin networks.",
                "Review configuration and confirm only approved encrypted management services remain enabled."
            ))

        if default_credentials:
            findings.append(Finding(
                "IOT-003", "critical", device_id,
                "Device metadata indicates default or shared credentials.",
                "Replace default/shared credentials with unique managed identities and rotate secrets through approved processes.",
                "Confirm unique credential assignment and successful rotation without exposing secret values."
            ))

        if not segmented:
            findings.append(Finding(
                "IOT-004", "high", device_id,
                "Device is not assigned to an approved segmented network zone.",
                "Place the device in a dedicated trust zone with least-privilege east/west and north/south policy.",
                "Validate network policy and confirm only approved flows are permitted."
            ))

        if not telemetry_encrypted:
            findings.append(Finding(
                "IOT-005", "high", device_id,
                "Telemetry is marked as unencrypted.",
                "Enable an approved encrypted transport and certificate/key management process.",
                "Confirm transport encryption in configuration and authorized telemetry inspection."
            ))

        if not auto_update:
            findings.append(Finding(
                "IOT-006", "medium", device_id,
                "Automatic update capability is disabled or unavailable.",
                "Define a monitored manual update cadence with ownership, maintenance windows, and exception handling.",
                "Review patch records and confirm the device meets the documented update SLA."
            ))

    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)


def summarize(findings: list[Finding]) -> dict[str, int]:
    result = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        result[finding.severity] += 1
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python src/iot_analyzer.py data/devices.json")
        return 2
    findings = analyze(load_devices(sys.argv[1]))
    print(json.dumps({"summary": summarize(findings), "findings": [asdict(f) for f in findings]}, indent=2))
    return 1 if any(f.severity in {"high", "critical"} for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
