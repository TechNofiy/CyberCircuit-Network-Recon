# Changelog

## V5.0
- Preserved all V4 behavior and added a separate Flagged Device Inventory directly below Device inventory.
- Summarizes observed high/medium-priority port observations with evidence, rationale and suggested next checks.
- Each flagged device opens a detailed evidence panel including hostname availability, ping/TCP observations, scope, timestamp and limitations.
- Flags are review prompts based on selected open TCP ports, not claims that a device is compromised or vulnerable.


## V4.0
- Preserved V3 dashboard, plugins, reports, history, build lab and source backup.
- Added an explicit permission checkbox and server-side confirmation requirement before network scans.
- Added user-selected TCP port lists/ranges, with validation and a 256-port cap; LAN targets remain RFC1918 IPv4 and at most 256 addresses.
- Added detailed clickable port/finding cards with service context, plain-language meaning, suggested review steps and limitations.
- Displays informational observations as well as higher-priority review items; no exploitation, credential attempts, or remote control.

## V3.0
- Added Docker-based cross-platform build scaffolds for a harmless diagnostic CLI.
- Preserved the V2 dashboard, plugins, reports and history.

## V2.0
- Added defensive plugin workbench, TLS/web-header audits, DNS lookup, host inventory and reporting.
