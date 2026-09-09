# IoT Remediation and Validation

## Firmware lifecycle
**Impact:** unsupported firmware may retain unpatched vulnerabilities and weak cryptographic or management components.

**Remediation:** upgrade to a vendor-supported release or replace the device under a risk-approved lifecycle plan.

**Validation:** record vendor support evidence, deployed version, change record, and a follow-up inventory check.

## Insecure management protocols
**Impact:** cleartext or legacy management protocols can expose credentials and administrative traffic.

**Remediation:** disable Telnet/FTP/HTTP/SNMPv1/v2c where possible; require approved encrypted alternatives and restrict access to management networks.

**Validation:** configuration review plus authorized network-flow evidence confirming only approved management services remain.

## Default/shared credentials
**Impact:** compromise of one shared secret can expose multiple devices.

**Remediation:** issue unique managed identities, rotate credentials, and document ownership without storing secret values in evidence.

**Validation:** confirm unique identity assignment and successful rotation through the approved secrets-management process.

## Segmentation
**Impact:** flat placement increases lateral-movement opportunities after device compromise.

**Remediation:** move devices into dedicated trust zones with allow-listed communications.

**Validation:** inspect intended policy, review flow telemetry, and confirm denied paths remain blocked.

## Closure standard
Findings are closed only after the original control passes, evidence is attached, ownership is clear, and any exception is time-bounded with compensating controls.