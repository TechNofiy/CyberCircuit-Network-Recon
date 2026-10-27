# CyberCircuit Network Recon V5

**Platform:** Windows 10/11 · **UI:** Local web dashboard · **Runtime:** Python 3.10+  
**Design:** V1 dark/cyan dashboard retained; V2 defensive plugin workbench preserved; V3 added a Docker-based cross-platform build lab; V4 added permission-gated port assessment and detailed clickable findings; V5 adds a dedicated flagged-device review panel beneath the main inventory.

## What's new in V5

- Separate **Flagged Device Inventory** directly below Device inventory.
- Evidence-based high/medium review queue with observed ports, reasons and recommended next checks.
- Click any flagged device for detailed observed information and scan limitations.

## What's new in V4

- Requires an explicit permission confirmation in the GUI and again on the server before starting a scan.
- Lets you choose comma-separated TCP ports or a port range, capped at 256 ports per scan; LAN scope remains private IPv4 and up to 256 addresses.
- Every open port has a clickable detail card explaining likely service purpose, what reachability means, recommended checks, severity context and limitations. Informational results are shown too; an open port alone is not proof of a vulnerability.
- No exploit attempts, password/login attempts, or attempts to compromise devices.
- Adds a Cross-Platform Build Lab that generates a ZIP project for a harmless Go system-information CLI.
- Select Linux, Windows or macOS plus supported CPU architecture targets. Docker builds the diagnostic binary from source; install Docker Desktop/Engine separately.
- Adds Device Fleet workflow notes for explicit, authenticated, manually installed management agents.
- No reverse-shell generator, arbitrary remote shell, covert agent deployment, persistence or credential collection.

## V2 features retained

- Retains V1's dashboard styling, LAN inventory table, activity log, common TCP-port observations and CSV/JSON export.
- Faster but bounded concurrent checks for small authorised LAN ranges.
- Strictly restricts network scans to RFC1918 private IPv4 ranges: `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`, up to 256 addresses per scan.
- Adds an extendable plugin structure in `plugins/`; plugin enable/disable settings are stored in `config.json`.
- Adds DNS/reverse DNS lookup, TLS certificate audit, HTTP security-header review, local host profile and Windows TCP connection-state summary.
- Adds scan progress, recent scan history, module result history and combined JSON reports.
- Adds localhost/Origin checks for POST requests; the service binds to `127.0.0.1` only.
- Preserves the original V1 source in `V1-backup/` for reference.

## Start the dashboard

1. Extract the ZIP into a normal writable folder, e.g. `C:\Tools\CyberCircuit-Network-Recon-V3`.
2. Install Python 3.10 or newer from <https://www.python.org/downloads/> if needed. Enable **Add Python to PATH**.
3. Double-click `BUILD-WINDOWS.bat` to run a syntax/build check.
4. Double-click `START-CyberCircuit.bat`.
5. Open <http://127.0.0.1:8765> in your browser.

No pip packages are required for the dashboard. Docker is optional unless you use the Build Lab. The first run creates `config.json` when you change a plugin's enabled state. Close the console window or press Ctrl+C in it to stop the server.

## Build Lab

Open the dashboard and select a target OS and architecture in **Cross-Platform Build Lab**, then choose **Generate build project ZIP**. Extract the ZIP and run `BUILD-WINDOWS.bat` on Windows or `build.sh` on macOS/Linux. Docker must be installed and running. The output is written to `dist/`. The generated program only prints basic host/runtime metadata. Review the generated source before running it.

The Docker build scaffold supports Linux (amd64, arm64, ARMv7), Windows (amd64, arm64), and macOS (amd64, arm64). Actual execution must occur on a compatible operating system.

## Built-in modules

| Module | Purpose |
|---|---|
| LAN scanner | Finds responsive hosts on an authorised RFC1918 subnet and checks selected user-selected TCP ports (up to 256 per scan). |
| DNS & Reverse DNS | Resolves a hostname or looks up a PTR name for an IP. |
| TLS Certificate Audit | Validates a target's TLS certificate using the local system trust store, then reports issuer and expiry. |
| Web Security Headers | Sends a HEAD request and reviews common security headers. It does not follow redirects or download page content. |
| Local Host Profile | Read-only OS, Python, machine architecture and local-address summary. |
| Process Inventory | Read-only capped sample of local process names, PIDs and memory use; no process actions. |
| Connection Snapshot | On Windows, summarises local TCP connection states using `netstat -ano`; does not capture packet contents. |
| Windows Security Posture | Best-effort read-only Windows Firewall profile and Microsoft Defender status summary. |
| Reports & History | Keeps recent scan summaries and module results in memory and exports JSON/CSV. |

### Add a plugin

1. Create a Python module under `plugins/`, such as `plugins/example_check.py`.
2. Add a `PLUGIN` dictionary with `id`, `name`, `description`, `category`, `requires_target`, `placeholder` and `button` fields.
3. Implement `run(target: str)` and return JSON-serialisable data. Raise `ValueError` for validation failures.
4. Import the module in `app.py` and add it to `PLUGIN_MODULES`. Keep the module allowlist explicit; do not load plugin modules from user-submitted names or paths.
5. Run `BUILD-WINDOWS.bat`, then restart the dashboard.

## Safety boundaries

This project is for inventory and defensive checks on systems and services you own or are authorised to assess. The dashboard is not an exploitation or post-exploitation framework. It deliberately does **not** include covert command-and-control, arbitrary remote shell, payload/stager generation, persistence, privilege escalation, keylogging, screenshot capture, email extraction, credential theft, evasion or propagation. The BYOB inspiration is limited to a modular interface and separable feature plugins.

TLS and HTTP observations are not a full penetration test. DNS results and open ports can change; manually verify anything important. Web audit targets must be valid hostnames/IPs and avoid loopback, link-local and special-purpose addresses. Private RFC1918 addresses are allowed for a local homelab audit.

## Troubleshooting

- **Python not found:** install Python 3.10+ and check **Add Python to PATH**.
- **Port 8765 is in use:** close the other application or change `PORT` in `app.py`.
- **A scan finds few devices:** verify the CIDR with `ipconfig`, then check host firewalls and device state. ICMP may be blocked.
- **TLS test fails:** the service may have an expired, self-signed or name-mismatched certificate, or the host may not offer TLS on the selected port.
- **Web headers show an HTTP error:** the server may not support HEAD, require authentication or return a redirect. V2 intentionally does not retry with GET.
- **Plugin settings won't save:** extract the ZIP to a folder where your Windows account can write `config.json`.

## Privacy

No cloud service or external telemetry is used by the app. Web/DNS/TLS modules contact only the target you explicitly enter. The dashboard is designed for localhost and should not be port-forwarded or exposed to a public network.

## Run offline checks

From the extracted project folder, run:

```bat
py -3 -m unittest discover -s tests -v
```

The tests validate local-only scope rules, plugin registration, target validation and core GUI content. They do not run a network scan against an actual LAN.


### V5 Flagged Device Inventory
A dedicated panel below Device inventory summarizes devices with high/medium-priority observations from the selected open TCP ports. Click a flagged device for the evidence, why it was flagged, practical follow-up checks, and scan limitations. These are triage indicators, not confirmed vulnerabilities.
