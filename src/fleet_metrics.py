from __future__ import annotations

from collections import Counter
from typing import Any

RISK_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def calculate_fleet_metrics(devices: list[dict[str, Any]], findings: list[Any]) -> dict[str, Any]:
    total_devices = len(devices)
    affected_devices = {str(getattr(finding, "device_id", "unknown")) for finding in findings}
    severities = Counter(str(getattr(finding, "severity", "low")) for finding in findings)
    by_device = Counter(str(getattr(finding, "device_id", "unknown")) for finding in findings)

    weighted_risk = sum(RISK_WEIGHTS.get(severity, 1) * count for severity, count in severities.items())
    maximum_reasonable = max(total_devices * RISK_WEIGHTS["critical"] * 3, 1)
    normalized_risk_score = min(round((weighted_risk / maximum_reasonable) * 100, 1), 100.0)

    return {
        "total_devices": total_devices,
        "affected_devices": len(affected_devices),
        "affected_device_percentage": round((len(affected_devices) / total_devices) * 100, 1) if total_devices else 0.0,
        "findings_by_severity": {level: severities.get(level, 0) for level in ("critical", "high", "medium", "low")},
        "normalized_risk_score": normalized_risk_score,
        "highest_finding_count_devices": [
            {"device_id": device_id, "finding_count": count}
            for device_id, count in by_device.most_common(5)
        ],
    }


def remediation_priority(metrics: dict[str, Any]) -> str:
    critical = int(metrics["findings_by_severity"].get("critical", 0))
    high = int(metrics["findings_by_severity"].get("high", 0))
    if critical:
        return "immediate"
    if high >= 3:
        return "accelerated"
    if high:
        return "planned-high"
    return "standard"
