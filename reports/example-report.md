# Example IoT Security Assessment Report

> Synthetic portfolio output only. No production or client data is represented.

## Executive summary
The sample fleet contains one high-risk camera with unsupported firmware, Telnet enabled, shared/default credential risk, missing segmentation, and no automatic update capability. A gateway also exposes SNMPv2c and transmits unencrypted telemetry. The temperature sensor meets the modeled baseline.

## Prioritized findings

| ID | Severity | Affected sample | Impact | Recommended action |
|---|---|---|---|---|
| IOT-002 | Critical | iot-cam-001 / iot-gateway-003 | Legacy management protocol exposure | Disable legacy services and restrict management plane |
| IOT-003 | Critical | iot-cam-001 | Credential reuse/default-account exposure | Issue unique managed identity and rotate credentials |
| IOT-001 | High | iot-cam-001 | Unsupported firmware risk | Upgrade or replace under lifecycle plan |
| IOT-004 | High | iot-cam-001 | Increased lateral-movement exposure | Segment into dedicated IoT trust zone |
| IOT-005 | High | iot-gateway-003 | Telemetry confidentiality/integrity risk | Enable approved encrypted transport |
| IOT-006 | Medium | iot-cam-001 | Patch-governance weakness | Establish monitored update cadence |

## Validation evidence expected
- Supported firmware/version evidence
- Approved management-protocol configuration
- Identity/credential-rotation record without secret values
- Network segmentation policy and flow validation
- Encrypted telemetry configuration
- Updated inventory showing the original control failures resolved
