# Defensive IoT Threat Model

## Assets
- Device identity and management interfaces
- Firmware and update mechanism
- Telemetry and control traffic
- Network segmentation boundaries
- Local configuration and credentials

## Trust boundaries
1. Device to management plane
2. Device to telemetry broker/service
3. IoT network to enterprise network
4. Vendor update channel to device

## Primary defensive scenarios

| Scenario | Security concern | ATT&CK context | Preventive/detective controls |
|---|---|---|---|
| Legacy management service exposed | Initial access / credential exposure | External Remote Services context | Disable legacy protocols, restrict management plane, monitor connections |
| Default/shared device credentials | Credential abuse | Valid Accounts context | Unique identities, rotation, secrets governance, authentication telemetry |
| Flat IoT/enterprise network | Lateral movement | Remote Services context | Segmentation, least privilege ACLs, NAC, flow monitoring |
| Unsupported firmware | Known-vulnerability exposure | Exploitation context | Lifecycle inventory, vendor advisories, upgrade/replace plan |
| Unencrypted telemetry | Loss of confidentiality/integrity | Adversary-in-the-Middle context | TLS/mTLS where supported, certificate governance |

ATT&CK references provide defensive context only and are not intended as execution instructions.

## Security objectives
- Maintain complete device ownership and lifecycle records.
- Minimize exposed management surfaces.
- Enforce unique identity and credential controls.
- Isolate device trust zones from user/server networks.
- Protect telemetry confidentiality and integrity.
- Validate remediation with configuration and network evidence.
