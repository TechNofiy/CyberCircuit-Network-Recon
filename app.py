#!/usr/bin/env python3
"""CyberCircuit Network Recon V5 — permission-gated local inventory, flagged-device review and build lab."""
from __future__ import annotations

import csv
import ipaddress
import io
import json
import platform
import socket
import subprocess
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from plugins import connection_snapshot, dns_lookup, local_host, process_inventory, tls_audit, web_headers, windows_posture

APP_DIR = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = 8765
MAX_HOSTS = 256
MAX_REQUEST_BYTES = 4096
SAFE_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 5432, 5900, 8080, 8443]
MAX_CUSTOM_PORTS = 256
RFC1918 = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
PLUGIN_MODULES = [dns_lookup, tls_audit, web_headers, local_host, process_inventory, connection_snapshot, windows_posture]
PLUGIN_BY_ID = {m.PLUGIN["id"]: m for m in PLUGIN_MODULES}
CONFIG_PATH = APP_DIR / "config.json"


def _load_config():
    try:
        saved = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        saved = {}
    raw = saved.get("plugins", {}) if isinstance(saved, dict) else {}
    return {pid: bool(raw.get(pid, True)) for pid in PLUGIN_BY_ID}


PLUGIN_ENABLED = _load_config()
STATE = {
    "running": False, "status": "Ready", "started_at": None, "finished_at": None,
    "target": None, "devices": [], "logs": [], "error": None,
    "module_results": [], "history": [], "progress": 0,
}
LOCK = threading.RLock()


def now_local():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def log(message, level="info"):
    item = {"time": now_local(), "level": level, "message": str(message)[:1000]}
    with LOCK:
        STATE["logs"].append(item)
        STATE["logs"] = STATE["logs"][-500:]


def private_network(value: str):
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 CIDR, e.g. 192.168.1.0/24.") from exc
    if net.version != 4 or not any(net.subnet_of(allowed) for allowed in RFC1918):
        raise ValueError("For safety, scans are restricted to RFC1918 private IPv4 LAN ranges (10/8, 172.16/12, 192.168/16).")
    if net.num_addresses > MAX_HOSTS:
        raise ValueError("Range is too large. Use a /24 or smaller range (maximum 256 addresses).")
    return net


def reverse_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def check_port(ip, port, timeout=0.22):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def ping_host(ip):
    # ICMP is only a hint; many devices block ping so TCP checks are also performed.
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", "450", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5, check=False)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


PORT_CATALOG = {
    20: ("FTP data", "Legacy file-transfer data channel", "Confirm FTP is required; prefer modern encrypted file transfer."),
    21: ("FTP", "File Transfer Protocol", "Traditional FTP may expose credentials or data without encryption. Prefer SFTP/FTPS."),
    22: ("SSH", "Secure Shell remote administration", "Common on servers and network devices. Verify patching, key-based authentication and access restrictions."),
    23: ("Telnet", "Unencrypted remote terminal", "High-priority review: Telnet is unencrypted. Disable it or restrict it and use SSH."),
    25: ("SMTP", "Mail transfer service", "Check whether this host should accept mail and ensure it is not an open relay."),
    53: ("DNS", "Domain Name System", "Expected on resolvers and servers. Confirm recursion and zone transfers are restricted appropriately."),
    80: ("HTTP", "Unencrypted web service", "HTTP is not automatically a vulnerability. Check redirects, data sensitivity and whether HTTPS is also available."),
    110: ("POP3", "Legacy mail retrieval", "Plain POP3 may expose mail credentials. Prefer POP3S or IMAPS where applicable."),
    139: ("NetBIOS session", "Legacy Windows file-sharing service", "Review whether legacy NetBIOS is required and restrict it to trusted networks."),
    143: ("IMAP", "Mail retrieval service", "Confirm TLS is required for clients and access is limited to intended networks."),
    443: ("HTTPS", "TLS-protected web service", "Expected for secure websites and admin consoles. Certificate and configuration checks are separate."),
    445: ("SMB", "Windows file sharing", "Ensure file sharing is needed, patched, and limited to trusted hosts. Internet exposure is especially risky."),
    3306: ("MySQL", "Database listener", "Database ports are usually best restricted to application hosts, not broad user networks."),
    3389: ("RDP", "Remote Desktop Protocol", "Restrict remote desktop to trusted hosts or VPN and use strong authentication and MFA where available."),
    5432: ("PostgreSQL", "Database listener", "Restrict database access to application hosts and verify authentication and patching."),
    5900: ("VNC", "Remote desktop service", "Restrict remote desktop access and use secure authentication or a protected tunnel."),
    6379: ("Redis", "In-memory data store", "Should not be broadly exposed. Confirm authentication, network restrictions and safe bind settings."),
    8080: ("HTTP alternate", "Alternate web or application port", "Could be a development server, proxy or web app. Identify the owner and check authentication."),
    8443: ("HTTPS alternate", "Alternate TLS web service", "Often used for admin consoles or applications. Verify access controls and certificate settings."),
    9200: ("Elasticsearch", "Search/index API", "Review authentication and network restrictions; data APIs should not be open to untrusted clients."),
}

def port_info(port):
    if port in PORT_CATALOG:
        name, purpose, advice = PORT_CATALOG[port]
    else:
        try:
            name = socket.getservbyport(port, "tcp")
        except OSError:
            name = "Unknown / application-specific service"
        purpose = "TCP listener; the port number alone cannot reliably identify the application."
        advice = "Confirm the service owner, expected exposure, authentication, patch level and firewall rules. Do not assume an open port is a vulnerability."
    severity = "high" if port == 23 else "medium" if port in (21, 445, 3389, 5900, 3306, 5432, 6379, 9200) else "info"
    return {"severity": severity, "title": f"TCP {port} open — {name}", "detail": purpose + " " + advice,
            "port": port, "service": name, "purpose": purpose, "recommendation": advice,
            "what_it_means": f"A TCP connection to port {port} succeeded from this computer at scan time. This confirms reachability, not that the service is exploitable or misconfigured.",
            "limitations": "Port-number labels are clues, not proof of service identity. No exploit attempts or authentication attempts were made."}

def risk_findings(open_ports):
    return [port_info(port) for port in open_ports]

def parse_ports(value):
    if value in (None, "", []):
        return SAFE_PORTS[:]
    ports = set()
    if isinstance(value, list):
        parts = value
    elif isinstance(value, str):
        parts = value.replace(" ", "").split(",")
    else:
        raise ValueError("Ports must be a comma-separated list or array.")
    for item in parts:
        raw = str(item)
        if not raw:
            continue
        if "-" in raw:
            bits = raw.split("-")
            if len(bits) != 2 or not all(x.isdigit() for x in bits):
                raise ValueError("Port ranges must look like 1-1024.")
            lo, hi = map(int, bits)
            if lo < 1 or hi > 65535 or hi < lo or hi - lo + 1 > MAX_CUSTOM_PORTS:
                raise ValueError("Each range must be valid and contain at most 256 ports.")
            ports.update(range(lo, hi + 1))
        else:
            if not raw.isdigit() or not 1 <= int(raw) <= 65535:
                raise ValueError(f"Invalid TCP port: {raw}")
            ports.add(int(raw))
        if len(ports) > MAX_CUSTOM_PORTS:
            raise ValueError("Select at most 256 TCP ports per scan.")
    if not ports:
        raise ValueError("Choose at least one TCP port.")
    return sorted(ports)

def scan_one(ip, ports):
    reachable = ping_host(ip)
    open_ports = [port for port in ports if check_port(ip, port, timeout=0.35)]
    if not reachable and not open_ports:
        return None
    return {"ip": ip, "hostname": reverse_name(ip), "reachable_by_ping": reachable,
        "open_ports": open_ports, "findings": risk_findings(open_ports), "checked_at": now_local(),
        "ports_checked": len(ports), "assessment_note": "Reachability inventory only; no exploitation or login attempts."}

def scan_worker(cidr, ports):
    try:
        net = private_network(cidr)
        hosts = [str(addr) for addr in net.hosts()]
        if not hosts:
            hosts = [str(net.network_address)]
        log(f"Starting permission-confirmed LAN inventory for {net} ({len(hosts)} address(es), {len(ports)} TCP port(s) per host).")
        devices = []
        # Bounded concurrency improves responsiveness without creating an aggressive scan.
        with ThreadPoolExecutor(max_workers=min(32, max(1, len(hosts)))) as pool:
            for idx, device in enumerate(pool.map(lambda ip: scan_one(ip, ports), hosts), 1):
                with LOCK:
                    STATE["progress"] = round(idx * 100 / len(hosts))
                    STATE["status"] = f"Checking authorised LAN ({idx}/{len(hosts)})"
                if device:
                    devices.append(device)
                    log(f"Discovered {device['ip']}: {len(device['open_ports'])} TCP port(s) open; {len(device['findings'])} detail card(s).")
        finished = now_local()
        with LOCK:
            STATE["devices"] = sorted(devices, key=lambda d: tuple(int(part) for part in d["ip"].split(".")))
            STATE["status"] = "Scan complete"
            STATE["finished_at"] = finished
            STATE["running"] = False
            STATE["progress"] = 100
            STATE["error"] = None
            STATE["history"].append({"target": str(net), "device_count": len(devices), "finished_at": finished})
            STATE["history"] = STATE["history"][-50:]
        log(f"Finished. Found {len(devices)} responsive device(s).")
    except Exception as exc:
        with LOCK:
            STATE["error"] = str(exc)
            STATE["status"] = "Scan failed"
            STATE["running"] = False
        log(str(exc), "error")


def plugin_info():
    return [{**module.PLUGIN, "enabled": PLUGIN_ENABLED[module.PLUGIN["id"]]} for module in PLUGIN_MODULES]


def save_config():
    payload = {"plugins": PLUGIN_ENABLED}
    temp = CONFIG_PATH.with_suffix(".json.tmp")
    temp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temp.replace(CONFIG_PATH)


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberCircuit Network Recon V5</title>
<style>
:root{color-scheme:dark;--bg:#070b13;--panel:#101827;--line:#24344a;--cyan:#35d7f2;--muted:#9aabc1;--green:#65e6a5;--amber:#ffc66d}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 20% 0%,#10243a 0,transparent 45%),var(--bg);color:#eaf4ff;font:15px/1.5 Segoe UI,Arial,sans-serif}
header{padding:26px max(22px,calc((100vw - 1200px)/2));border-bottom:1px solid var(--line);background:#080e18d9}
.brand{color:var(--cyan);letter-spacing:.16em;font-size:12px;font-weight:800}.title{font-size:clamp(25px,4vw,38px);font-weight:800;margin:4px 0}.sub{color:var(--muted)}
main{max-width:1200px;margin:auto;padding:22px;display:grid;gap:18px}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.modulegrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.panel,.stat,.module-card{background:linear-gradient(145deg,#111c2c,#0c1320);border:1px solid var(--line);border-radius:15px;padding:18px;min-width:0}
h2{font-size:16px;margin:0 0 12px}.stat small{display:block;color:var(--muted)}.num{font-size:28px;font-weight:800;color:var(--cyan)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.grow{flex:1}input{background:#080e18;border:1px solid #31445d;border-radius:9px;padding:12px;color:#fff;min-width:230px;flex:1}
button,.btn{border:1px solid #2a8da5;background:#12384a;color:#eaffff;padding:11px 15px;border-radius:9px;font-weight:700;cursor:pointer;text-decoration:none}button:hover,.btn:hover{background:#18516a}button:disabled{opacity:.5;cursor:not-allowed}.secondary{background:#172234;border-color:#34455b}
.note{border-left:3px solid var(--amber);padding:10px 12px;background:#211c13;color:#f8dfb7;border-radius:4px;font-size:13px}
.muted{color:var(--muted);font-size:13px}.status{color:var(--green);font-weight:700}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;border-bottom:1px solid var(--line);padding:10px 8px;vertical-align:top}th{color:var(--muted);font-weight:600}td{overflow-wrap:anywhere}.pill{display:inline-block;border:1px solid #34516a;border-radius:99px;padding:2px 8px;margin:2px;font-size:12px}.high{color:#ff8f8f}.medium{color:var(--amber)}.info{color:var(--cyan)}.logs{height:240px;overflow:auto;background:#060a10;border:1px solid var(--line);padding:10px;border-radius:9px;font:12px/1.6 Consolas,monospace}.logline{border-bottom:1px solid #121d2a;padding:3px 0}.error{color:#ff8f8f}
.module-card{padding:15px}.module-top{display:flex;gap:10px;align-items:flex-start;justify-content:space-between}.module-name{font-weight:800}.category{color:var(--cyan);font-size:11px;font-weight:800;letter-spacing:.1em;text-transform:uppercase}.module-desc{color:var(--muted);font-size:13px;min-height:40px;margin:7px 0 12px}.module-actions{display:flex;gap:8px;flex-wrap:wrap}.module-actions input{min-width:120px;width:100%;flex-basis:100%}.module-badge{border:1px solid #36516a;border-radius:20px;padding:2px 8px;font-size:11px;white-space:nowrap}.module-badge.on{color:var(--green);border-color:#267252}.module-badge.off{color:var(--amber);border-color:#795b2b}.resultbox{white-space:pre-wrap;overflow-wrap:anywhere;max-height:380px;overflow:auto;background:#060a10;border:1px solid var(--line);padding:12px;border-radius:9px;font:12px/1.6 Consolas,monospace;min-height:54px}.smallmuted{font-size:12px;color:var(--muted)}
footer{max-width:1200px;margin:auto;padding:0 22px 28px;color:var(--muted);font-size:12px}
@media(max-width:760px){.grid,.modulegrid{grid-template-columns:1fr}main{padding:14px}.panel{padding:14px}header{padding:20px 16px}table{font-size:12px}}
.flag-high{color:#ff8585;font-weight:700}.flag-medium{color:#ffd479;font-weight:700}.flag-device{background:#101d2b;border:1px solid #31445d;border-radius:8px;padding:8px;white-space:normal;text-align:left;min-width:0}.flag-device:hover{border-color:var(--cyan)}.finding-link{display:block;text-align:left;width:100%;margin:4px 0;background:#101d2b;border-color:#31445d;font-weight:400;white-space:normal}.finding-link small{color:var(--cyan)}.port-pill{padding:4px 8px;margin:2px;min-width:0}.modal{position:fixed;inset:0;z-index:20;background:#02060de8;display:flex;align-items:center;justify-content:center;padding:20px}.modal-card{width:min(760px,100%);max-height:85vh;overflow:auto;background:#101827;border:1px solid var(--cyan);border-radius:16px;padding:20px;box-shadow:0 20px 90px #000}.detail-grid{display:grid;grid-template-columns:160px 1fr;gap:8px;padding:8px 0;border-bottom:1px solid var(--line)}.detail-grid b{color:var(--cyan)}@media(max-width:700px){.detail-grid{grid-template-columns:1fr;gap:2px}}
</style></head><body>
<header><div class="brand">CYBERCIRCUIT // SECURITY TOOLS</div><div class="title">Network Recon <span style="color:var(--cyan)">v3.0</span></div><div class="sub">LAN discovery · Modular audits · Cross-platform build lab · Exportable reports</div></header>
<main>
<div class="note"><b>Authorised use only.</b> LAN scans are restricted to RFC1918 private IPv4 ranges, up to 256 addresses. The dashboard binds to this PC only. Plugins perform read-only diagnostics and service checks; no payloads, stealth, persistence, credential collection or remote command execution.</div>
<section class="panel"><h2>Permission-gated LAN assessment</h2><div class="row"><input id="cidr" value="192.168.1.0/24" aria-label="Private network CIDR" placeholder="192.168.1.0/24"><input id="ports" value="21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,5900,6379,8080,8443,9200" aria-label="TCP ports to check" placeholder="22,80,443 or 1-1024"><button id="scan" onclick="startScan()">Start authorised scan</button><button class="secondary" onclick="refresh()">Refresh</button><span id="status" class="status">Ready</span></div><label style="display:block;margin-top:12px"><input id="permission" type="checkbox" style="min-width:0;flex:initial"> I own these systems or have explicit permission to assess this network and selected ports.</label><p class="muted">Only private IPv4 LAN ranges are allowed, up to 256 addresses. Choose comma-separated TCP ports or a range; at most 256 ports per scan. This performs connection checks and service classification only—not exploit attempts, logins, or device compromise.</p><div style="height:5px;background:#08111d;border-radius:6px;overflow:hidden"><div id="progress" style="width:0;height:100%;background:var(--cyan);transition:width .2s"></div></div></section>
<section class="grid"><div class="stat"><small>Responsive devices</small><div class="num" id="deviceCount">0</div></div><div class="stat"><small>Open selected ports</small><div class="num" id="portCount">0</div></div><div class="stat"><small>Findings to review</small><div class="num" id="findingCount">0</div></div></section>
<section class="panel"><div class="row"><h2 class="grow">Defensive Module Workbench</h2><span class="status" id="moduleCount">Loading plugins…</span></div><p class="muted">BYOB-inspired modular layout, adapted for legitimate inventory and security checks. Toggle modules on or off; enabled states are saved in config.json.</p><div class="modulegrid" id="modules"><div class="muted">Loading built-in modules…</div></div></section>
<section class="panel"><div class="row"><h2 class="grow">Cross-Platform Build Lab</h2><span class="status">Docker / Go</span></div>
<p class="muted">Generate a starter project for a harmless system-info diagnostic CLI. Choose a target OS and CPU architecture, then build inside Docker. This does not generate remote shells, payloads, persistence, or remote-execution agents.</p>
<div class="row"><label>Target OS <select id="buildOS"><option value="linux">Linux</option><option value="windows">Windows</option><option value="darwin">macOS</option></select></label>
<label>Architecture <select id="buildArch"><option value="amd64">x86_64 / amd64</option><option value="arm64">ARM64</option><option value="arm">ARMv7 (Linux only)</option></select></label>
<button onclick="downloadBuildScaffold()">Generate build project ZIP</button></div>
<p class="smallmuted" id="buildStatus">Output: source code, Dockerfile, and build scripts. Docker must be installed to compile the selected target.</p></section>
<section class="panel"><div class="row"><h2 class="grow">Device Fleet Notes</h2><span class="module-badge">Manual / opt-in</span></div><p class="muted">Use the LAN inventory above to discover devices. V3 does not silently install software on discovered devices. For remote administration, install a trusted management agent manually on each device and use its documented authenticated controls.</p><div class="resultbox">Recommended workflow
1. Scan only your own private LAN.
2. Confirm the device owner and intended scope.
3. Install an approved management agent manually.
4. Require authentication, visible consent, least-privilege permissions, and audit logs.
5. Remove access when the test is complete.</div></section>
<section class="panel"><div class="row"><h2 class="grow">Latest module result</h2><button class="secondary" onclick="clearModuleResult()">Clear view</button></div><div class="resultbox" id="moduleResult">Run a module to see the results here.</div><div class="smallmuted" id="moduleResultMeta" style="margin-top:8px">Results stay on this PC and are included in the JSON report.</div></section>
<section class="panel"><div class="row"><h2 class="grow">Device inventory</h2><button class="secondary" onclick="downloadReport('json')">Export JSON</button><button class="secondary" onclick="downloadReport('csv')">Export CSV</button></div><div style="overflow:auto"><table><thead><tr><th>IP / Hostname</th><th>Ping</th><th>Open ports</th><th>Security observations</th></tr></thead><tbody id="devices"><tr><td colspan="4" class="muted">No results yet. Confirm permission, select scope and start an assessment.</td></tr></tbody></table></div></section>
<section class="panel"><div class="row"><h2 class="grow">⚑ Flagged device inventory</h2><span class="status" id="flaggedCount">0 devices flagged</span></div><p class="muted">A focused review list for devices with higher-priority observations. Flags are based on observed open TCP ports and are not proof of a vulnerability. Click a device to see the evidence, why it was flagged, practical next checks, and scan limitations.</p><div style="overflow:auto"><table><thead><tr><th>Device</th><th>Priority</th><th>Observed evidence</th><th>Why it is flagged</th><th>Next step</th></tr></thead><tbody id="flaggedDevices"><tr><td colspan="5" class="muted">No flagged devices yet. Run an authorised scan to populate this list.</td></tr></tbody></table></div><div id="flaggedSummary" class="resultbox" style="margin-top:12px">This panel will show a summary of flagged devices after a scan.</div></section>
<section class="panel"><h2>Recent scan history</h2><div style="overflow:auto"><table><thead><tr><th>Completed</th><th>Target</th><th>Devices</th></tr></thead><tbody id="history"><tr><td colspan="3" class="muted">No completed scans in this session.</td></tr></tbody></table></div></section>
<section class="panel"><h2>Live activity log</h2><div id="logs" class="logs" aria-live="polite">[ready] Dashboard started. Waiting for scan.</div></section>
<section class="panel"><h2>Scope & limitations</h2><div class="muted">LAN scans use ICMP ping and TCP connection checks for the ports you select (up to 256). Devices may block ping or port checks, so absence from results does not prove a device is offline. Web-header checks use HEAD requests only and do not follow redirects or download page content. TLS checks verify certificates using the operating system trust store. Observations are prompts for manual review, not proof of vulnerabilities.</div></section>
<div id="detailModal" class="modal" style="display:none" role="dialog" aria-modal="true" aria-labelledby="detailTitle"><div class="modal-card"><div class="row"><h2 class="grow" id="detailTitle">Finding details</h2><button class="secondary" onclick="closeDetails()">Close ✕</button></div><div id="detailBody" class="resultbox"></div></div></div>
</main><footer>CyberCircuit Network Recon V5 · 127.0.0.1 only · No cloud uploads or external telemetry · Standard-library Python; no third-party dependencies.</footer>
<script>
let lastState={};let pluginList=[];let findingLookup={};
async function api(path,opts={}){const r=await fetch(path,opts);let d={};try{d=await r.json()}catch(e){}if(!r.ok)throw new Error(d.error||'Request failed');return d}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function startScan(){const btn=document.getElementById('scan');if(!document.getElementById('permission').checked){alert('Confirm that you own these systems or have explicit permission before scanning.');return}btn.disabled=true;try{await api('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cidr:document.getElementById('cidr').value,ports:document.getElementById('ports').value,permission:true})});await refresh()}catch(e){alert(e.message)}finally{btn.disabled=!!lastState.running}}
async function refresh(){try{lastState=await api('/api/state');render(lastState)}catch(e){document.getElementById('status').textContent='Server unavailable'}}
function render(s){document.getElementById('status').textContent=s.status+(s.running?'…':'');document.getElementById('scan').disabled=s.running;document.getElementById('progress').style.width=(s.progress||0)+'%';
const dev=s.devices||[];document.getElementById('deviceCount').textContent=dev.length;document.getElementById('portCount').textContent=dev.reduce((n,d)=>n+(d.open_ports||[]).length,0);document.getElementById('findingCount').textContent=dev.reduce((n,d)=>n+(d.findings||[]).length,0);
const tbody=document.getElementById('devices');findingLookup={};if(!dev.length){tbody.innerHTML='<tr><td colspan="4" class="muted">No responsive devices recorded yet.</td></tr>'}else{tbody.innerHTML=dev.map((d,di)=>{const cards=(d.findings||[]).map((f,fi)=>{const id='f'+di+'_'+fi;findingLookup[id]={...f,ip:d.ip,hostname:d.hostname||'',checked_at:d.checked_at};return '<button class="finding-link '+esc(f.severity)+'" onclick="showFinding(\''+id+'\')"><b>'+esc(f.severity.toUpperCase())+': '+esc(f.title)+'</b><br><span>'+esc(f.purpose||f.detail)+'</span><br><small>Click for full explanation ↗</small></button>'}).join('');return '<tr><td><b>'+esc(d.ip)+'</b><br><span class="muted">'+esc(d.hostname||'Hostname unavailable')+'</span></td><td>'+(d.reachable_by_ping?'Yes':'TCP only')+'</td><td>'+((d.open_ports||[]).length?d.open_ports.map(p=>'<button class="pill port-pill" onclick="showPort(\''+d.ip+'\','+p+')">'+p+'</button>').join(''):'—')+'</td><td>'+(cards||'<button class="finding-link info" onclick="showDeviceInfo(\''+d.ip+'\')">No open ports in selected set — click for details</button>')+'</td></tr>'}).join('')}
// Keep a dedicated, evidence-based queue for devices whose observed ports merit closer review.
const flagged=(dev||[]).map(d=>({...d,priority:(d.findings||[]).some(f=>f.severity==='high')?'high':(d.findings||[]).some(f=>f.severity==='medium')?'medium':'',flaggedFindings:(d.findings||[]).filter(f=>f.severity==='high'||f.severity==='medium')})).filter(d=>d.priority);
document.getElementById('flaggedCount').textContent=flagged.length+' device'+(flagged.length===1?'':'s')+' flagged';
const ft=document.getElementById('flaggedDevices');
if(!flagged.length){ft.innerHTML='<tr><td colspan="5" class="muted">No higher-priority flags in the current results. Informational open ports remain available in Device inventory above; no flags does not mean a device is guaranteed secure.</td></tr>';document.getElementById('flaggedSummary').textContent=dev.length?'Scanned '+dev.length+' responsive device(s). No devices matched the current high/medium review rules. Check informational observations in the main inventory and consider whether each exposed service is expected.':'No scan results yet.';}
else{ft.innerHTML=flagged.map((d,i)=>{const evidence=d.flaggedFindings.map(f=>'TCP '+f.port+' '+f.service+' ('+f.severity+')').join(', ');const why=d.flaggedFindings.map(f=>f.purpose).join(' ');const next=d.flaggedFindings.map(f=>f.recommendation).filter(Boolean).join(' ');return '<tr><td><button class="flag-device" data-flag-index="'+i+'"><b>'+esc(d.ip)+'</b><br><span class="muted">'+esc(d.hostname||'Hostname unavailable')+'</span><br><small>Click for device details ↗</small></button></td><td class="flag-'+esc(d.priority)+'">'+esc(d.priority.toUpperCase())+'</td><td>'+esc(evidence)+'</td><td>'+esc(why)+'</td><td>'+esc(next)+'</td></tr>'}).join('');
ft.querySelectorAll('[data-flag-index]').forEach(b=>b.addEventListener('click',()=>{const d=flagged[Number(b.dataset.flagIndex)];if(!d)return;showDetails('Flagged device · '+d.ip,[['Hostname',d.hostname||'Unavailable'],['Priority',d.priority.toUpperCase()],['Observed evidence',d.flaggedFindings.map(f=>'TCP '+f.port+' — '+f.service+' ('+f.severity+')').join('; ')],['Why flagged',d.flaggedFindings.map(f=>f.purpose).join(' ')],['What the scan confirmed',d.flaggedFindings.map(f=>f.what_it_means).join(' ')],['Recommended next checks',d.flaggedFindings.map(f=>f.recommendation).join(' ')],['Ping',d.reachable_by_ping?'Responded':'No ping response; TCP reachability was observed'],['Ports checked',d.ports_checked],['Assessment limitation',d.assessment_note+' Port classification is based on port number; no exploit or login attempts were made.'],['Observed at',d.checked_at]])}));
document.getElementById('flaggedSummary').textContent=flagged.length+' device(s) need closer review based on selected TCP ports. Highest priority: '+flagged.filter(d=>d.priority==='high').length+' high; '+flagged.filter(d=>d.priority==='medium').length+' medium. These are review prompts, not confirmed vulnerabilities. Verify service ownership, intended exposure, firewall rules, authentication, and patch status on the device.';}
const logs=document.getElementById('logs');logs.innerHTML=(s.logs||[]).slice(-150).map(l=>'<div class="logline '+(l.level==='error'?'error':'')+'">['+esc((l.time||'').split('T').pop())+'] '+esc(l.message)+'</div>').join('');logs.scrollTop=logs.scrollHeight;
const hist=document.getElementById('history');hist.innerHTML=(s.history||[]).length?(s.history||[]).slice().reverse().map(h=>'<tr><td>'+esc(h.finished_at)+'</td><td>'+esc(h.target)+'</td><td>'+esc(h.device_count)+'</td></tr>').join(''):'<tr><td colspan="3" class="muted">No completed scans in this session.</td></tr>';}
async function loadPlugins(){try{const d=await api('/api/plugins');pluginList=d.plugins||[];renderPlugins()}catch(e){document.getElementById('modules').textContent='Could not load plugins: '+e.message}}
function renderPlugins(){const root=document.getElementById('modules');document.getElementById('moduleCount').textContent=pluginList.filter(p=>p.enabled).length+' / '+pluginList.length+' enabled';if(!pluginList.length){root.innerHTML='<div class="muted">No plugins found.</div>';return}
root.innerHTML=pluginList.map(p=>'<article class="module-card"><div class="module-top"><div><div class="category">'+esc(p.category)+'</div><div class="module-name">'+esc(p.name)+'</div></div><span class="module-badge '+(p.enabled?'on':'off')+'">'+(p.enabled?'ENABLED':'DISABLED')+'</span></div><div class="module-desc">'+esc(p.description)+'</div><div class="module-actions">'+(p.requires_target?'<input id="target-'+esc(p.id)+'" placeholder="'+esc(p.placeholder)+'" aria-label="Target for '+esc(p.name)+'">':'')+'<button '+(!p.enabled?'disabled':'')+' data-run="'+esc(p.id)+'">'+esc(p.button)+'</button><button class="secondary" data-toggle="'+esc(p.id)+'" data-enable="'+(!p.enabled)+'">'+(p.enabled?'Disable':'Enable')+'</button></div></article>').join('');root.querySelectorAll('[data-run]').forEach(b=>b.addEventListener('click',()=>runModule(b.dataset.run)));root.querySelectorAll('[data-toggle]').forEach(b=>b.addEventListener('click',()=>togglePlugin(b.dataset.toggle,b.dataset.enable==='true')))}
async function togglePlugin(id,enabled){try{const d=await api('/api/plugin/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({plugin:id,enabled})});pluginList=d.plugins;renderPlugins();await refresh()}catch(e){alert(e.message)}}
async function runModule(id){const p=pluginList.find(x=>x.id===id);if(!p||!p.enabled)return;const input=document.getElementById('target-'+id);const target=input?input.value.trim():'';const out=document.getElementById('moduleResult');out.textContent='Running '+p.name+'…';document.getElementById('moduleResultMeta').textContent='Module executing locally.';try{const d=await api('/api/plugin/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({plugin:id,target})});out.textContent=JSON.stringify(d.result,null,2);document.getElementById('moduleResultMeta').textContent=p.name+' · '+d.completed_at+' · Local result';await refresh()}catch(e){out.textContent='Module failed: '+e.message;document.getElementById('moduleResultMeta').textContent=p.name+' · Error';await refresh()}}
function clearModuleResult(){document.getElementById('moduleResult').textContent='Run a module to see the results here.';document.getElementById('moduleResultMeta').textContent='Results stay on this PC and are included in the JSON report.'}
async function downloadReport(fmt){try{const r=await fetch('/api/report?format='+fmt);if(!r.ok){let e={};try{e=await r.json()}catch(_){}throw new Error(e.error||'Export failed')}const blob=await r.blob();const a=document.createElement('a');const url=URL.createObjectURL(blob);a.href=url;a.download='cybercircuit-network-report.'+(fmt==='csv'?'csv':'json');a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}catch(e){alert(e.message)}}
async function downloadBuildScaffold(){
 const os=document.getElementById('buildOS').value, arch=document.getElementById('buildArch').value, status=document.getElementById('buildStatus');
 if(arch==='arm' && os!=='linux'){status.textContent='ARMv7 is supported only for Linux in this scaffold.';return}
 status.textContent='Preparing safe starter project…';
 try { const r=await fetch('/api/build/scaffold',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({os,arch})});
 if(!r.ok){let e={};try{e=await r.json()}catch(_){}throw new Error(e.error||'Build project generation failed')}
 const blob=await r.blob(), url=URL.createObjectURL(blob), a=document.createElement('a');a.href=url;a.download='cybercircuit-build-'+os+'-'+arch+'.zip';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);status.textContent='Project ZIP generated. Extract it, then run the included build script with Docker installed.';
 } catch(e){status.textContent='Error: '+e.message}
}
function showDetails(title,fields){document.getElementById('detailTitle').textContent=title;document.getElementById('detailBody').innerHTML=fields.map(([k,v])=>'<div class="detail-grid"><b>'+esc(k)+'</b><div>'+esc(v||'Not available')+'</div></div>').join('');document.getElementById('detailModal').style.display='flex'}
function showFinding(id){const f=findingLookup[id];if(!f)return;showDetails(f.title,[['Device',f.ip+(f.hostname?' · '+f.hostname:'')],['Severity / category',String(f.severity||'info').toUpperCase()],['Service',f.service],['What this means',f.what_it_means||f.detail],['Purpose',f.purpose],['Recommended review',f.recommendation||f.detail],['Limitations',f.limitations],['Observed at',f.checked_at]])}
function showPort(ip,port){const f=Object.values(findingLookup).find(x=>x.ip===ip&&x.port===port);if(f){showDetails('TCP '+port+' — '+f.service,[['Device',ip],['Port',port],['Service label',f.service],['Purpose',f.purpose],['What this means',f.what_it_means],['Recommended review',f.recommendation],['Limitations',f.limitations]]);return}showDetails('TCP '+port+' — open',[['Device',ip],['Port',port],['Meaning','A TCP connection to this port succeeded during the scan.'],['Caution','An open port is not, by itself, proof of a security problem.']])}
function showDeviceInfo(ip){const d=(lastState.devices||[]).find(x=>x.ip===ip);showDetails('Device '+ip,[['Hostname',d?.hostname||'Unavailable'],['Ping',d?.reachable_by_ping?'Responded':'No ping response; TCP reachability may still work'],['Ports checked',d?.ports_checked||'See scan scope'],['Assessment',d?.assessment_note||'No selected TCP port responded. This does not prove the device is offline.'],['Last checked',d?.checked_at||'Not available']])}
function closeDetails(){document.getElementById('detailModal').style.display='none'}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDetails()});
refresh();loadPlugins();setInterval(refresh,1500);setInterval(loadPlugins,10000);
</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberCircuitRecon/5.0"

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, body):
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _allowed_local_request(self):
        # The app is localhost-only; also reject cross-site browser POSTs.
        host = (self.headers.get("Host") or "").split(":", 1)[0].strip("[]").lower()
        if host not in ("127.0.0.1", "localhost"):
            return False
        origin = self.headers.get("Origin")
        if origin:
            try:
                parsed = urlparse(origin)
                origin_port = parsed.port
            except ValueError:
                return False
            if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost") or origin_port not in (None, PORT):
                return False
        return True

    def _read_json(self):
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError as exc:
            raise ValueError("Invalid content length.") from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("Request too large.")
        try:
            value = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Request body must be valid JSON.") from exc
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object.")
        return value

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            return self.send_html(PAGE)
        if path == "/api/state":
            with LOCK:
                data = {**STATE, "devices": list(STATE["devices"]), "logs": list(STATE["logs"]),
                        "module_results": list(STATE["module_results"]), "history": list(STATE["history"])}
            return self.send_json(data)
        if path == "/api/plugins":
            return self.send_json({"plugins": plugin_info()})
        if path == "/api/build/targets":
            return self.send_json({"targets": [{"os": "linux", "architectures": ["amd64", "arm64", "arm"]}, {"os": "windows", "architectures": ["amd64", "arm64"]}, {"os": "darwin", "architectures": ["amd64", "arm64"]}]})
        if path == "/api/report":
            fmt = parse_qs(urlparse(self.path).query).get("format", ["json"])[0].lower()
            if fmt not in ("json", "csv"):
                return self.send_json({"error": "Unsupported format. Use json or csv."}, 400)
            with LOCK:
                snapshot = {
                    "version": "4.0", "generated_at": datetime.now(timezone.utc).isoformat(),
                    "target": STATE["target"], "devices": list(STATE["devices"]),
                    "module_results": list(STATE["module_results"]), "history": list(STATE["history"]),
                }
            if fmt == "csv":
                out = io.StringIO(newline="")
                writer = csv.writer(out)
                writer.writerow(["ip", "hostname", "reachable_by_ping", "open_ports", "finding_severities", "findings"])
                for d in snapshot["devices"]:
                    writer.writerow([d["ip"], d["hostname"], d["reachable_by_ping"], ";".join(map(str, d["open_ports"])),
                                     ";".join(f["severity"] for f in d["findings"]),
                                     " | ".join(f'{f["title"]}: {f["detail"]}' for f in d["findings"])])
                body = out.getvalue().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="cybercircuit-network-report.csv"')
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            body = json.dumps(snapshot, indent=2, default=str).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="cybercircuit-network-report.json"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        return self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        if not self._allowed_local_request():
            return self.send_json({"error": "Local requests only; cross-site requests are blocked."}, 403)
        path = urlparse(self.path).path
        try:
            payload = self._read_json()
        except ValueError as exc:
            return self.send_json({"error": str(exc)}, 400)

        if path == "/api/build/scaffold":
            target_os = str(payload.get("os", "linux"))
            arch = str(payload.get("arch", "amd64"))
            allowed = {"linux": {"amd64", "arm64", "arm"}, "windows": {"amd64", "arm64"}, "darwin": {"amd64", "arm64"}}
            if target_os not in allowed or arch not in allowed[target_os]:
                return self.send_json({"error": "Unsupported OS/architecture combination."}, 400)
            goarch = {"amd64": "amd64", "arm64": "arm64", "arm": "arm"}[arch]
            goarm = "\nENV GOARM=7" if arch == "arm" else ""
            ext = ".exe" if target_os == "windows" else ""
            main_go = '''package main

import (
    "fmt"
    "os"
    "runtime"
    "time"
)

// CyberCircuit harmless diagnostic CLI: reports basic runtime metadata only.
// It does not open network listeners, execute commands, or collect secrets.
func main() {
    host, _ := os.Hostname()
    fmt.Println("CyberCircuit Diagnostic CLI")
    fmt.Printf("Hostname: %s\nOS: %s\nArchitecture: %s\nGo: %s\nTime: %s\n", host, runtime.GOOS, runtime.GOARCH, runtime.Version(), time.Now().Format(time.RFC3339))
}
'''
            dockerfile = f"""FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS build
WORKDIR /src
COPY main.go .
ARG TARGETOS={target_os}
ARG TARGETARCH={goarch}
{goarm}
ENV CGO_ENABLED=0
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/diagnostic{ext} main.go
FROM scratch AS export
COPY --from=build /out/diagnostic{ext} /diagnostic{ext}
"""
            readme = f"""# CyberCircuit Build Lab starter

Target: {target_os}/{arch}

This is a benign system-metadata diagnostic CLI. It prints hostname, OS, architecture, Go version and local time. It contains no network listener, reverse shell, remote command execution, persistence, or credential collection.

## Build with Docker

```sh
docker build --build-arg TARGETOS={target_os} --build-arg TARGETARCH={goarch} --output type=local,dest=dist .
```

The build exports the compiled file into a local `dist/` folder. For a Windows target, the output is `dist/diagnostic.exe`. Docker Desktop or Docker Engine must be installed. macOS cross-builds can be produced but the resulting executable must be run on macOS.

Review the source before building and run only on systems you own or administer.
"""
            build_bat = f"@echo off\r\necho Building CyberCircuit harmless diagnostic for {target_os}/{arch}\r\ndocker build --build-arg TARGETOS={target_os} --build-arg TARGETARCH={goarch} --output type=local,dest=dist .\r\nif errorlevel 1 pause\r\n"
            build_sh = f"#!/bin/sh\nset -eu\ndocker build --build-arg TARGETOS={target_os} --build-arg TARGETARCH={goarch} --output type=local,dest=dist .\n"
            mem = io.BytesIO()
            with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("main.go", main_go)
                zf.writestr("Dockerfile", dockerfile)
                zf.writestr("README.md", readme)
                zf.writestr("BUILD-WINDOWS.bat", build_bat)
                zf.writestr("build.sh", build_sh)
            body = mem.getvalue()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="cybercircuit-build-{target_os}-{arch}.zip"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            log(f"Generated safe diagnostic build scaffold for {target_os}/{arch}.")
            return

        if path == "/api/scan":
            try:
                if payload.get("permission") is not True:
                    return self.send_json({"error": "Explicit permission confirmation is required before scanning."}, 403)
                net = private_network(str(payload.get("cidr", "")).strip())
                ports = parse_ports(payload.get("ports"))
                with LOCK:
                    if STATE["running"]:
                        return self.send_json({"error": "A scan is already running."}, 409)
                    STATE.update({"running": True, "status": "Starting scan", "started_at": now_local(),
                                  "finished_at": None, "target": str(net), "devices": [], "error": None, "progress": 0, "logs": [], "ports": ports})
                log(f"Queued scan for {net}.")
                threading.Thread(target=scan_worker, args=(str(net), ports), daemon=True, name="ccr-lan-scan").start()
                return self.send_json({"ok": True, "target": str(net)}, 202)
            except ValueError as exc:
                return self.send_json({"error": str(exc)}, 400)

        if path == "/api/plugin/toggle":
            plugin_id = str(payload.get("plugin", ""))
            enabled = payload.get("enabled")
            if plugin_id not in PLUGIN_BY_ID or not isinstance(enabled, bool):
                return self.send_json({"error": "Unknown plugin or invalid enabled value."}, 400)
            with LOCK:
                PLUGIN_ENABLED[plugin_id] = enabled
                try:
                    save_config()
                except OSError as exc:
                    log(f"Could not save plugin settings: {exc}", "error")
                    return self.send_json({"error": "Could not save plugin settings to config.json."}, 500)
            log(f"Plugin {'enabled' if enabled else 'disabled'}: {PLUGIN_BY_ID[plugin_id].PLUGIN['name']}.")
            return self.send_json({"plugins": plugin_info()})

        if path == "/api/plugin/run":
            plugin_id = str(payload.get("plugin", ""))
            target = str(payload.get("target", "")).strip()
            module = PLUGIN_BY_ID.get(plugin_id)
            if module is None:
                return self.send_json({"error": "Unknown plugin."}, 404)
            if not PLUGIN_ENABLED.get(plugin_id, False):
                return self.send_json({"error": "This plugin is disabled. Enable it first."}, 409)
            if len(target) > 2048:
                return self.send_json({"error": "Target is too long."}, 400)
            try:
                log(f"Running module: {module.PLUGIN['name']}.")
                result = module.run(target)
                completed = now_local()
                record = {"plugin": plugin_id, "name": module.PLUGIN["name"], "completed_at": completed,
                          "status": "success", "target": target or None, "result": result}
                with LOCK:
                    STATE["module_results"].append(record)
                    STATE["module_results"] = STATE["module_results"][-100:]
                log(f"Module completed: {module.PLUGIN['name']}.")
                return self.send_json({"ok": True, "plugin": plugin_id, "completed_at": completed, "result": result})
            except Exception as exc:
                message = str(exc)[:600] or "Module failed."
                log(f"Module error ({module.PLUGIN['name']}): {message}", "error")
                return self.send_json({"error": message}, 400)

        return self.send_json({"error": "Not found"}, 404)

    def log_message(self, fmt, *args):
        # Keep HTTP request messages in the console, not the visible activity log.
        print("%s - %s" % (self.address_string(), fmt % args))


def main():
    print("CyberCircuit Network Recon V5")
    print(f"Open http://{HOST}:{PORT} in your browser.")
    print("Bound to localhost only; LAN scans restricted to RFC1918 private IPv4 ranges.")
    print(f"Loaded {len(PLUGIN_MODULES)} defensive plugins.")
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
        server.daemon_threads = True
    except OSError as exc:
        print(f"Could not start web server on {HOST}:{PORT}: {exc}")
        print("Close the other program using port 8765 or change PORT in app.py.")
        input("Press Enter to exit…")
        return
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping CyberCircuit Network Recon V3…")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
