# BYOB-inspired module mapping

CyberCircuit Network Recon V2 uses BYOB as a reference for modular organisation, not as a source of copied payloads or command-and-control code.

| BYOB concept | CyberCircuit V2 equivalent | Implementation boundary |
|---|---|---|
| Port scanner | LAN discovery + selected TCP service inventory | RFC1918 private IPv4 only; maximum 256 addresses. |
| Security utilities | TLS certificate audit + HTTP security-header review | Read-only checks against the explicit target; no exploit attempts. |
| General utilities | DNS/reverse DNS + local host profile | No remote execution. |
| Process inventory | Process Inventory plugin | Local read-only sample; never kills or modifies a process. |
| Packet sniffer | Connection Snapshot | Summarises local TCP states; does not capture packet contents or credentials. |
| Host/system checks | Windows Security Posture | Reads firewall profile and Defender status; no settings changed. |
| C2 database and HTTP result handler | Local scan history + module-result list + JSON/CSV reporting | Results remain in local process memory unless the user exports a report. |
| Dynamic module organisation | Explicit allowlisted Python plugin registry | Only modules installed in `plugins/` and registered in `app.py` run; no remote module downloads. |

## Deliberately not included

V2 does not include BYOB-style reverse shell/command-and-control, arbitrary remote command execution, payload or stager generation, persistence, privilege escalation/UAC bypass, keylogging, screenshot capture, email extraction, credential collection, stealth/evasion or network propagation. Those capabilities are not needed for a defensive LAN inventory tool and would materially change its risk profile.
