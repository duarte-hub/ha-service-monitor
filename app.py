"""
Home Assistant Service Monitor
Monitors Z-Wave JS UI, Zigbee2MQTT, and SLZB coordinator health.
Provides a live web dashboard and email alerts.
"""

import os
import re
import time
import json
import uuid
import logging
import smtplib
import ipaddress
import threading
import xml.etree.ElementTree as ET
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from datetime import datetime, timezone, timedelta

import socket
import subprocess

import websocket
import requests
from flask import Flask, render_template, jsonify, request, redirect

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
VERSION = "1.1.0"

# ---------------------------------------------------------------------------
# Configuration (all via environment variables)
# ---------------------------------------------------------------------------
HA_URL = os.environ.get("HA_URL", "http://192.168.0.20:8123")
HA_TOKEN = os.environ.get("HA_TOKEN", "")
POLL_INTERVAL        = int(os.environ.get("POLL_INTERVAL",        "30"))   # device ping loop
HA_POLL_INTERVAL     = int(os.environ.get("HA_POLL_INTERVAL",     "30"))   # HA add-on status
MERAKI_POLL_INTERVAL = int(os.environ.get("MERAKI_POLL_INTERVAL", "300"))  # Meraki API clients

# Email config
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
EMAIL_FROM      = os.environ.get("EMAIL_FROM", SMTP_USER)
EMAIL_FROM_NAME = os.environ.get("EMAIL_FROM_NAME", "Farol")
EMAIL_TO = os.environ.get("EMAIL_TO", "")
ALERT_COOLDOWN = int(os.environ.get("ALERT_COOLDOWN", "300"))  # seconds
NOTIFY_SERVICE = os.environ.get("NOTIFY_SERVICE", "notify.mobile_app_iphoned")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_LOG_BUFFER: list[dict] = []
_LOG_BUFFER_MAX = 2000

class _BufferHandler(logging.Handler):
    def emit(self, record):
        try:
            msg = record.getMessage()
            if record.exc_info and not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
            if record.exc_text:
                msg += "\n" + record.exc_text
            _LOG_BUFFER.append({
                "ts":    datetime.fromtimestamp(record.created).strftime("%H:%M:%S"),
                "level": record.levelname,
                "src":   "http" if record.name == "werkzeug" else record.threadName,
                "msg":   msg,
            })
            if len(_LOG_BUFFER) > _LOG_BUFFER_MAX:
                del _LOG_BUFFER[0]
        except Exception:
            self.handleError(record)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
)
log = logging.getLogger("farol")
_buf_handler = _BufferHandler()
_buf_handler.setFormatter(logging.Formatter("%(message)s"))
_buf_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(_buf_handler)

def _set_verbose(enabled: bool) -> None:
    level = logging.DEBUG if enabled else logging.INFO
    logging.getLogger().setLevel(level)
    _buf_handler.setLevel(level)

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Shared state
monitor_state = {
    "last_poll": None,
    "services": {},
    "coordinators": {},
    "ha_reachable": False,
    "ha_version": "",
    "peer_status": {},
}
state_lock = threading.Lock()
def _atomic_write(path: str, data) -> None:
    """Write JSON atomically: write to .tmp then rename so a crash mid-write never corrupts the original."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)

_Z2M_STATUS_PATH = os.environ.get("Z2M_STATUS_PATH", "/data/z2m_last_update_status.json")
def _load_z2m_status() -> dict:
    try:
        with open(_Z2M_STATUS_PATH) as fh:
            return json.load(fh)
    except Exception:
        return {"state": "idle", "message": "", "log": []}

def _persist_z2m_status(status: dict) -> None:
    try:
        _atomic_write(_Z2M_STATUS_PATH, status)
    except Exception:
        pass

z2m_update_status: dict = _load_z2m_status()
alert_history: dict[str, float] = {}  # key -> last alert timestamp
_ALERTS_STATE_PATH = os.environ.get("ALERTS_STATE_PATH", "/data/alerts_enabled.json")
alerts_enabled: bool = True

def _load_alerts_enabled() -> bool:
    try:
        with open(_ALERTS_STATE_PATH) as fh:
            return json.load(fh).get("enabled", True)
    except Exception:
        return True

def _persist_alerts_enabled(val: bool) -> None:
    try:
        _atomic_write(_ALERTS_STATE_PATH, {"enabled": val})
    except Exception:
        pass

alerts_enabled = _load_alerts_enabled()

# ---------------------------------------------------------------------------
# Network device store
# ---------------------------------------------------------------------------
SCAN_NETWORK  = os.environ.get("SCAN_NETWORK", "")   # e.g. 192.168.0.0/24
PING_INTERVAL = int(os.environ.get("PING_INTERVAL", "30"))
SCAN_PORTS    = os.environ.get("SCAN_PORTS", "22,80,443,8080,8123,1883,8883")

_DEVICES_PATH = os.environ.get("DEVICES_PATH", "/data/devices.json")
_devices: dict[str, dict] = {}
_devices_lock = threading.Lock()
_scan_status: dict = {"state": "idle", "message": ""}

def _load_devices() -> dict:
    try:
        with open(_DEVICES_PATH) as fh:
            devices = {d["ip"]: d for d in json.load(fh)}
        for d in devices.values():
            d["port_status"] = {}  # always re-check on startup so down ports re-alert
        return devices
    except Exception:
        return {}

def _save_devices() -> None:
    try:
        _atomic_write(_DEVICES_PATH, sorted(_devices.values(), key=lambda d: [int(x) for x in d["ip"].split(".")]))
    except Exception as e:
        log.error("Failed to save devices: %s", e)

_devices = _load_devices()

def _local_network() -> str:
    if SCAN_NETWORK:
        return SCAN_NETWORK
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
    except Exception:
        return "192.168.0.0/24"

def _parse_nmap_xml(xml: str) -> list[dict]:
    out = []
    try:
        root = ET.fromstring(xml)
        for host in root.findall("host"):
            st = host.find("status")
            if st is None or st.get("state") != "up":
                continue
            ip = mac = vendor = hostname = None
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
                elif addr.get("addrtype") == "mac":
                    mac  = addr.get("addr")
                    vendor = addr.get("vendor", "")
            hn_el = host.find("hostnames/hostname")
            if hn_el is not None:
                hostname = hn_el.get("name")
            if ip:
                out.append({"ip": ip, "mac": mac or "", "vendor": vendor or "", "hostname": hostname or ""})
    except Exception as e:
        log.error("nmap XML parse error: %s", e)
    return out

def _parse_nmap_ports_xml(xml: str) -> dict[str, list[int]]:
    """Return {ip: [open_port, ...]} from an nmap port-scan XML blob."""
    out: dict[str, list[int]] = {}
    try:
        root = ET.fromstring(xml)
        for host in root.findall("host"):
            st = host.find("status")
            if st is None or st.get("state") != "up":
                continue
            ip = None
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
            if not ip:
                continue
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            open_ports = []
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    try:
                        open_ports.append(int(port_el.get("portid", 0)))
                    except ValueError:
                        pass
            if open_ports:
                out[ip] = open_ports
    except Exception as e:
        log.error("nmap ports XML parse error: %s", e)
    return out


def _do_port_scan(ips: list[str], ports_str: str) -> None:
    """Scan specific ports on a list of IPs; merge any open ports into device records."""
    if not ips or not ports_str.strip():
        return
    try:
        result = subprocess.run(
            ["nmap", "-p", ports_str.strip(), "-T4", "--host-timeout", "10s", "-oX", "-"] + ips,
            capture_output=True, text=True, timeout=300,
        )
        port_map = _parse_nmap_ports_xml(result.stdout)
        log.info("Port scan: %d/%d hosts had open ports in [%s]", len(port_map), len(ips), ports_str)
        with _devices_lock:
            changed = False
            for ip, open_ports in port_map.items():
                if ip not in _devices:
                    continue
                existing = set(_devices[ip].get("ports") or [])
                merged = sorted(existing | set(open_ports))
                if merged != sorted(existing):
                    new_ports = sorted(set(open_ports) - existing)
                    log.info("Port scan %s: discovered open ports %s", ip, new_ports)
                    _devices[ip]["ports"] = merged
                    changed = True
            if changed:
                _save_devices()
    except Exception as e:
        log.error("Port scan failed: %s", e)


def _do_scan(network: str) -> None:
    global _scan_status
    _scan_status = {"state": "running", "message": f"Scanning {network}…"}
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-oX", "-", "--host-timeout", "5s", network],
            capture_output=True, text=True, timeout=180,
        )
        found = _parse_nmap_xml(result.stdout)
        now = datetime.now(timezone.utc).isoformat()
        with _devices_lock:
            for d in found:
                ip  = d["ip"]
                old = _devices.get(ip, {})
                _devices[ip] = {
                    "ip":             ip,
                    "mac":            d["mac"]      or old.get("mac", ""),
                    "vendor":         d["vendor"]   or old.get("vendor", ""),
                    "hostname":       d["hostname"] or old.get("hostname", ""),
                    "name":           old.get("name", ""),
                    "monitored":      old.get("monitored", False),
                    "alert_mode":     old.get("alert_mode", "default"),
                    "status":         "up",
                    "last_seen":      now,
                    "ping_latency_ms": old.get("ping_latency_ms"),
                }
            _save_devices()
        if found and SCAN_PORTS:
            _scan_status = {"state": "running", "message": f"Port scanning {len(found)} hosts…"}
            _do_port_scan([d["ip"] for d in found], SCAN_PORTS)
        _scan_status = {"state": "done", "message": f"Found {len(found)} devices", "count": len(found), "network": network}
        log.info("Network scan complete: %d devices on %s", len(found), network)
    except Exception as e:
        _scan_status = {"state": "error", "message": str(e)}
        log.error("Network scan failed: %s", e)

def _ping_host(ip: str) -> tuple[bool, float | None]:
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "2", ip],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            m = re.search(r"time=(\d+\.?\d*)", r.stdout)
            latency = float(m.group(1)) if m else None
            log.debug("ping %s: up  %.1fms", ip, latency or 0)
            return True, latency
        log.debug("ping %s: down", ip)
        return False, None
    except Exception:
        log.debug("ping %s: error", ip)
        return False, None

def _check_port(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            log.debug("port %s:%s: open", ip, port)
            return True
    except Exception:
        log.debug("port %s:%s: closed", ip, port)
        return False

# ---------------------------------------------------------------------------
# BER / SNMP primitives
# ---------------------------------------------------------------------------
def _ber_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    elif n < 256:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xff])


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _ber_decode(data: bytes, pos: int = 0):
    """Yield (tag, value_bytes) for each TLV at the current nesting level."""
    while pos < len(data):
        tag = data[pos]; pos += 1
        b   = data[pos]; pos += 1
        if b < 0x80:
            length = b
        elif b == 0x81:
            length = data[pos]; pos += 1
        elif b == 0x82:
            length = (data[pos] << 8) | data[pos + 1]; pos += 2
        else:
            break
        yield tag, data[pos: pos + length]
        pos += length


# OIDs to request in a single SNMP GET (BER-encoded, first two nodes: 1*40+3=0x2b)
_SNMP_OIDS = [
    bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]),  # sysDescr.0
    bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00]),  # sysName.0
    bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00]),  # sysLocation.0
]


def _snmp_parse_strings(data: bytes) -> list[str]:
    """Extract OCTET STRING values from each VarBind in an SNMP GET response."""
    strings: list[str] = []
    try:
        for tag, val in _ber_decode(data):
            if tag != 0x30:
                continue
            for tag2, val2 in _ber_decode(val):
                if tag2 != 0xA2:          # GetResponse-PDU
                    continue
                items = list(_ber_decode(val2))
                if len(items) < 4:
                    continue
                for tag3, val3 in _ber_decode(items[3][1]):   # VarBindList
                    if tag3 != 0x30:
                        continue
                    vb = list(_ber_decode(val3))
                    if len(vb) >= 2 and vb[1][0] == 0x04:     # OCTET STRING
                        strings.append(vb[1][1].decode("utf-8", errors="replace").strip())
                    else:
                        strings.append("")
    except Exception:
        pass
    return strings


def _snmp_probe(ip: str, community: str = "public", timeout: float = 2.0) -> dict | None:
    """
    Send SNMPv2c GET for sysDescr / sysName / sysLocation.
    Returns {sysDescr, sysName, sysLocation} on any response, None on no response.
    """
    varbinds = b"".join(
        _ber_tlv(0x30, _ber_tlv(0x06, oid) + b"\x05\x00") for oid in _SNMP_OIDS
    )
    pdu = _ber_tlv(
        0xA0,
        b"\x02\x04\x00\x00\x00\x01"  # request-id = 1
        b"\x02\x01\x00"              # error-status = 0
        b"\x02\x01\x00"              # error-index = 0
        + _ber_tlv(0x30, varbinds),
    )
    msg = _ber_tlv(
        0x30,
        b"\x02\x01\x01"             # version = v2c
        + _ber_tlv(0x04, community.encode())
        + pdu,
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msg, (ip, 161))
        data, _ = sock.recvfrom(4096)
        sock.close()
    except Exception:
        return None
    vals = _snmp_parse_strings(data)
    keys = ["sysDescr", "sysName", "sysLocation"]
    return {k: (vals[i] if i < len(vals) else "") for i, k in enumerate(keys)}


def _onvif_probe(ip: str, timeout: float = 3.0) -> bool:
    """Return True if device exposes an ONVIF device service on any common port."""
    soap = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        "<s:Body>"
        '<GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
        "</s:Body>"
        "</s:Envelope>"
    )
    headers = {"Content-Type": "application/soap+xml; charset=utf-8"}
    for port in [80, 8080, 8000, 8888]:
        try:
            r = requests.post(
                f"http://{ip}:{port}/onvif/device_service",
                data=soap, headers=headers, timeout=timeout,
            )
            if "onvif" in r.text.lower():
                return True
        except Exception:
            pass
    return False


# Port → display label for well-known services
_PORT_TAGS: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    502:  "Modbus",
    554:  "RTSP",
    873:  "rsync",
    1883: "MQTT",
    2049: "NFS",
    3260: "iSCSI",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP",
    8443: "HTTPS",
    9100: "Print",
}

_FEATURE_PROBE_INTERVAL = 600  # seconds


def _probe_device_features_once(ip: str, device: dict) -> dict:
    """Run SNMP + ONVIF probes; derive protocol tags from known open ports."""
    features: dict = dict(device.get("features") or {})

    # SNMP — rich info dict or None if no response
    snmp_info = _snmp_probe(ip, SNMP_COMMUNITY)
    features["snmp"]      = snmp_info is not None
    features["snmp_info"] = snmp_info or {}

    # ONVIF camera check
    features["onvif"] = _onvif_probe(ip)

    # Derive protocol tags from already-monitored open ports (zero extra probes)
    port_status = device.get("port_status") or {}
    seen:      set[str]  = set()
    protocols: list[str] = []
    for port_str, is_open in port_status.items():
        if not is_open:
            continue
        tag = _PORT_TAGS.get(int(port_str))
        if tag and tag not in seen:
            protocols.append(tag)
            seen.add(tag)

    # Probe RTSP (554) if not already in the monitored port list
    if "RTSP" not in seen and _check_port(ip, 554, timeout=2.0):
        protocols.append("RTSP")

    features["protocols"] = sorted(protocols)
    return features


def _feature_probe_loop() -> None:
    """Background thread: probe each monitored+up device for features every 10 min."""
    time.sleep(15)   # stagger startup
    while True:
        with _devices_lock:
            targets = [
                (ip, d.copy())
                for ip, d in _devices.items()
                if d.get("monitored") and d.get("status") == "up"
            ]
        for ip, dev in targets:
            try:
                features = _probe_device_features_once(ip, dev)
                log.debug("Feature probe %s: snmp=%s onvif=%s protocols=%s",
                          ip, features.get("snmp"), features.get("onvif"), features.get("protocols"))
                with _devices_lock:
                    if ip in _devices:
                        _devices[ip]["features"] = features
                _save_devices()
            except Exception as e:
                log.debug("Feature probe %s failed: %s", ip, e)
        time.sleep(_FEATURE_PROBE_INTERVAL)


def _seed_device(ip: str, name: str, ports: list[int]) -> None:
    with _devices_lock:
        if ip not in _devices:
            _devices[ip] = {
                "ip": ip, "mac": "", "vendor": "", "hostname": "",
                "name": name, "monitored": True, "alert_mode": "default",
                "status": "unknown", "last_seen": None, "ping_latency_ms": None,
                "ports": ports, "port_status": {},
            }
            log.info("Seeded device %s (%s) with ports %s", ip, name, ports)
        else:
            _devices[ip]["ports"] = ports
            log.info("Updated seed ports for %s: %s", ip, ports)
        _save_devices()

# ---------------------------------------------------------------------------
# Uptime history (in-memory ring buffer — not persisted, resets on restart)
# ---------------------------------------------------------------------------
_device_history: dict[str, list] = {}  # ip -> [{ts: float, up: bool}, ...]
_HISTORY_TTL = 90_000  # keep 25 h so the 24 h window is always fully populated


def _record_history(ip: str, up: bool) -> None:
    now  = time.time()
    hist = _device_history.setdefault(ip, [])
    hist.append({"ts": now, "up": up})
    cutoff = now - _HISTORY_TTL
    i = 0
    while i < len(hist) and hist[i]["ts"] < cutoff:
        i += 1
    if i:
        del hist[:i]


def _uptime_stats(ip: str) -> dict:
    hist = _device_history.get(ip, [])
    now  = time.time()
    def _pct(window: float):
        cutoff  = now - window
        samples = [e["up"] for e in hist if e["ts"] >= cutoff]
        return round(100 * sum(samples) / len(samples)) if samples else None
    return {"m1": _pct(60), "h1": _pct(3600), "h24": _pct(86400)}


def _history_buckets(ip: str) -> dict:
    """Return bucketed history arrays for sparkline rendering on the device page."""
    hist = _device_history.get(ip, [])
    now  = time.time()
    def _buckets(window: float, n: int) -> list:
        size = window / n
        result = []
        for i in range(n):
            t_end   = now - (n - 1 - i) * size
            t_start = t_end - size
            samples = [e["up"] for e in hist if t_start <= e["ts"] < t_end]
            result.append(round(100 * sum(samples) / len(samples)) if samples else None)
        return result
    return {
        "h1":  _buckets(3600,  30),   # 1 h  → 30 × 2-min buckets
        "h24": _buckets(86400, 48),   # 24 h → 48 × 30-min buckets
    }


def _ping_monitored() -> None:
    with _devices_lock:
        targets = [d.copy() for d in _devices.values() if d.get("monitored")]
    for dev in targets:
        ip   = dev["ip"]
        prev = dev.get("status", "unknown")
        up, latency = _ping_host(ip)
        now  = datetime.now(timezone.utc).isoformat()
        with _devices_lock:
            if ip not in _devices:
                continue
            _devices[ip]["status"]          = "up" if up else "down"
            _devices[ip]["ping_latency_ms"] = latency
            if up:
                _devices[ip]["last_seen"] = now
        _record_history(ip, up)
        label = dev.get("name") or dev.get("hostname") or ip
        mode  = dev.get("alert_mode") or "default"
        log.debug("monitored %s (%s): %s", label, ip, "up" if up else "down")
        if prev != "down" and not up:
            maybe_alert(f"device_{ip}", f"{label} unreachable", f"{ip} is not responding to ping", mode=mode)
        elif prev == "down" and up:
            log.info("Device %s (%s) is back online", label, ip)
            if notify_recovery:
                maybe_alert(f"device_{ip}_recovery", f"{label} back online", f"{ip} is responding again", mode=mode)

        ports = dev.get("ports") or []
        if ports:
            prev_ps = dev.get("port_status", {})
            new_ps  = {str(p): _check_port(ip, p) for p in ports}
            with _devices_lock:
                if ip in _devices:
                    _devices[ip]["port_status"] = new_ps
            for p_str, port_up in new_ps.items():
                prev_up = prev_ps.get(p_str)
                if prev_up is not False and not port_up:
                    maybe_alert(f"port_{ip}_{p_str}", f"{label} port {p_str} closed", f"{ip}:{p_str} is not responding", mode=mode)
                elif prev_up is False and port_up:
                    log.info("Port %s:%s back online", ip, p_str)
                    if notify_recovery:
                        maybe_alert(f"port_{ip}_{p_str}_recovery", f"{label} port {p_str} open", f"{ip}:{p_str} is responding again", mode=mode)

# ---------------------------------------------------------------------------
# SNMP device discovery
# ---------------------------------------------------------------------------
_SNMP_DEVICES_PATH = os.environ.get("SNMP_DEVICES_PATH", "/data/snmp_devices.json")
_snmp_devices: list[dict] = []
_snmp_lock = threading.Lock()
_mac_vendor_cache: dict[str, str] = {}

def _load_snmp_devices() -> list:
    try:
        with open(_SNMP_DEVICES_PATH) as fh:
            return json.load(fh)
    except Exception:
        return []

def _save_snmp_devices() -> None:
    try:
        _atomic_write(_SNMP_DEVICES_PATH, _snmp_devices)
    except Exception as e:
        log.error("Failed to save SNMP devices: %s", e)

_snmp_devices = _load_snmp_devices()

# MAC vendor lookup — calls api.macvendors.com once per OUI, caches to disk
_MAC_VENDOR_CACHE_PATH = os.environ.get("MAC_VENDOR_CACHE_PATH", "/data/mac_vendor_cache.json")
_mac_vendor_api_lock = threading.Lock()
_mac_vendor_last_call: float = 0.0

def _load_mac_vendor_cache() -> None:
    global _mac_vendor_cache
    try:
        with open(_MAC_VENDOR_CACHE_PATH) as fh:
            _mac_vendor_cache = json.load(fh)
    except Exception:
        _mac_vendor_cache = {}

def _save_mac_vendor_cache() -> None:
    try:
        _atomic_write(_MAC_VENDOR_CACHE_PATH, _mac_vendor_cache)
    except Exception:
        pass

_load_mac_vendor_cache()

def _mac_vendor(mac: str) -> str:
    global _mac_vendor_last_call
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    if oui in _mac_vendor_cache:
        return _mac_vendor_cache[oui]
    with _mac_vendor_api_lock:
        if oui in _mac_vendor_cache:
            return _mac_vendor_cache[oui]
        # Rate-limit: 1 req/s (free tier limit)
        wait = 1.1 - (time.time() - _mac_vendor_last_call)
        if wait > 0:
            time.sleep(wait)
        vendor = None
        try:
            resp = requests.get(
                f"https://api.macvendors.com/{mac[:8]}",
                timeout=5, headers={"Accept": "text/plain"},
            )
            _mac_vendor_last_call = time.time()
            if resp.status_code == 200:
                vendor = resp.text.strip()
            elif resp.status_code == 404:
                vendor = ""  # genuinely unknown OUI — cache permanently
        except Exception:
            pass
        if vendor is not None:  # don't cache on 429/timeout — retry next time
            _mac_vendor_cache[oui] = vendor
            _save_mac_vendor_cache()
        log.debug("MAC vendor %s → %s", oui, vendor or "(unknown)")
    return _mac_vendor_cache.get(oui, "")

def _snmpwalk(host: str, community: str, oid: str, timeout: int = 10, port: int = 161) -> list[tuple[str, str]]:
    """Run snmpwalk -v2c, return [(oid_str, value_str)] or [] on error."""
    try:
        target = f"{host}:{port}" if port != 161 else host
        r = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, "-On", target, oid],
            capture_output=True, text=True, timeout=timeout,
        )
        pairs = []
        for line in r.stdout.splitlines():
            if " = " not in line:
                continue
            oid_part, val_part = line.split(" = ", 1)
            val_part = val_part.strip()
            # Skip SNMP agent error responses that snmpwalk emits as result lines
            if val_part.startswith("No ") or val_part.startswith("NULL"):
                continue
            pairs.append((oid_part.strip(), val_part))
        log.debug("snmpwalk %s [%s]: %d rows", host, oid.split(".")[-1], len(pairs))
        return pairs
    except FileNotFoundError:
        log.warning("snmpwalk not found — install the snmp package")
        return []
    except Exception as e:
        log.debug("snmpwalk %s [%s]: %s", host, oid, e)
        return []

def _parse_snmp_mac(val_str: str) -> str:
    """Extract MAC from 'Hex-STRING: AA BB CC DD EE FF' style value."""
    hex_part = val_str.split(": ", 1)[-1] if ": " in val_str else val_str
    parts = re.findall(r"[0-9A-Fa-f]{2}", hex_part)
    if len(parts) == 6:
        return ":".join(p.lower() for p in parts)
    return ""

def _parse_meraki_mac_from_oid(oid_str: str) -> str:
    """Extract MAC from Meraki OID index (last 6 decimal octets)."""
    parts = oid_str.lstrip(".").split(".")
    if len(parts) < 6:
        return ""
    try:
        return ":".join(f"{int(b):02x}" for b in parts[-6:])
    except (ValueError, IndexError):
        return ""

# Meraki devTable OIDs (enterprises.29671.1.1.4)
_MERAKI_OID_DEV_NAME    = "1.3.6.1.4.1.29671.1.1.4.1.2"
_MERAKI_OID_DEV_STATUS  = "1.3.6.1.4.1.29671.1.1.4.1.3"
_MERAKI_OID_DEV_PRODUCT = "1.3.6.1.4.1.29671.1.1.4.1.10"
_MERAKI_OID_DEV_LAN_IP  = "1.3.6.1.4.1.29671.1.1.4.1.12"

def _poll_meraki_devtable(host: str, community: str, port: int = 161) -> dict[str, dict]:
    """Walk Meraki devTable; return {mac: {name, online, product}} per Meraki device."""
    result: dict[str, dict] = {}
    for oid_str, val_str in _snmpwalk(host, community, _MERAKI_OID_DEV_NAME, port=port):
        mac = _parse_meraki_mac_from_oid(oid_str)
        if mac:
            result.setdefault(mac, {})["name"] = val_str.replace("STRING:", "").strip().strip('"')
    for oid_str, val_str in _snmpwalk(host, community, _MERAKI_OID_DEV_STATUS, port=port):
        mac = _parse_meraki_mac_from_oid(oid_str)
        if mac:
            result.setdefault(mac, {})["online"] = val_str.strip() in ("1", "INTEGER: 1", "online(1)")
    for oid_str, val_str in _snmpwalk(host, community, _MERAKI_OID_DEV_PRODUCT, port=port):
        mac = _parse_meraki_mac_from_oid(oid_str)
        if mac:
            result.setdefault(mac, {})["product"] = val_str.replace("STRING:", "").strip().strip('"')
    # Also walk devLanIp to discover Meraki infrastructure IPs not already in ARP
    for oid_str, val_str in _snmpwalk(host, community, _MERAKI_OID_DEV_LAN_IP, port=port):
        mac = _parse_meraki_mac_from_oid(oid_str)
        if mac:
            ip_str = val_str.replace("IpAddress:", "").strip()
            if ip_str and ip_str != "0.0.0.0":
                result.setdefault(mac, {})["lan_ip"] = ip_str
    return result

def _poll_snmp_devices() -> int:
    """Query all enabled SNMP devices; return count of newly discovered IPs."""
    with _snmp_lock:
        targets = list(_snmp_devices)
    if not targets:
        return 0
    new_count = 0
    for dev in targets:
        if not dev.get("enabled", True):
            continue
        host = dev["host"]
        community = dev.get("community", "public")
        port = int(dev.get("port", 161) or 161)
        name = dev.get("name", host)
        log.info("SNMP querying %s (%s:%d)", name, host, port)

        # ARP table (ipNetToMedia): OID index is {ifIndex}.{ip0..3}, value is MAC
        ip_to_mac: dict[str, str] = {}
        for oid_str, val_str in _snmpwalk(host, community, "1.3.6.1.2.1.4.22.1.2", port=port):
            mac = _parse_snmp_mac(val_str)
            if not mac:
                continue
            parts = oid_str.lstrip(".").split(".")
            if len(parts) >= 4:
                ip = ".".join(parts[-4:])
                try:
                    socket.inet_aton(ip)
                    ip_to_mac[ip] = mac
                except Exception:
                    pass

        # Fallback: ipNetToPhysical (newer RFC 4293 table, supported by AOS-CX etc.)
        # OID index: {ifIndex}.{addrType}.{addrLen}.{ip octets}  — IPv4: addrType=1, len=4
        if not ip_to_mac:
            for oid_str, val_str in _snmpwalk(host, community, "1.3.6.1.2.1.4.35.1.4", port=port):
                mac = _parse_snmp_mac(val_str)
                if not mac:
                    continue
                parts = oid_str.lstrip(".").split(".")
                # IPv4 entries have addressType=1, addressLen=4 before the 4 IP octets
                if len(parts) >= 6 and parts[-6] == "1" and parts[-5] == "4":
                    ip = ".".join(parts[-4:])
                    try:
                        socket.inet_aton(ip)
                        ip_to_mac[ip] = mac
                    except Exception:
                        pass

        # Bridge forwarding table: value is MAC (covers wireless clients on APs too)
        bridge_macs: set[str] = set()
        for _oid, val_str in _snmpwalk(host, community, "1.3.6.1.2.1.17.4.3.1.1", port=port):
            mac = _parse_snmp_mac(val_str)
            if mac:
                bridge_macs.add(mac)

        # Meraki: walk devTable for infrastructure device names/status and LAN IPs
        meraki_devs: dict[str, dict] = {}
        if dev.get("type") == "meraki":
            meraki_devs = _poll_meraki_devtable(host, community, port=port)
            log.info("SNMP Meraki %s: %d infrastructure devices in devTable", name, len(meraki_devs))
            # Add Meraki infrastructure IPs not already in ARP table
            for mdev in meraki_devs.values():
                lan_ip = mdev.get("lan_ip", "")
                mac    = mdev.get("mac_key", "")  # set below
                if lan_ip and lan_ip not in ip_to_mac:
                    for m, d2 in meraki_devs.items():
                        if d2.get("lan_ip") == lan_ip:
                            ip_to_mac[lan_ip] = m
                            break

        log.info("SNMP %s: %d ARP entries, %d bridge MACs", name, len(ip_to_mac), len(bridge_macs))

        # Build mac→meraki_devs lookup keyed by MAC string
        meraki_by_mac = meraki_devs  # already keyed by mac string

        changed = False
        for ip, mac in ip_to_mac.items():
            if int(mac.split(":")[0], 16) & 0x01:
                continue  # skip multicast
            vendor = _mac_vendor(mac)
            meraki_info = meraki_by_mac.get(mac, {})
            meraki_dev_name = meraki_info.get("name", "")
            meraki_online   = meraki_info.get("online")
            meraki_product  = meraki_info.get("product", "")
            with _devices_lock:
                if ip not in _devices:
                    _devices[ip] = {
                        "ip": ip, "mac": mac, "vendor": vendor,
                        "hostname": "", "name": meraki_dev_name,
                        "learned_from": name,
                        "meraki_status": ("online" if meraki_online else "offline") if meraki_online is not None else None,
                        "meraki_product": meraki_product,
                        "monitored": False, "alert_mode": "default", "status": "unknown",
                        "last_seen": None, "ping_latency_ms": None,
                        "ports": [], "port_status": {},
                    }
                    log.info("SNMP discovered %s — %s (%s) via %s", ip, mac, vendor or "unknown vendor", name)
                    new_count += 1
                    changed = True
                else:
                    d = _devices[ip]
                    if not d.get("mac") and mac:
                        _devices[ip]["mac"] = mac
                        changed = True
                    if not d.get("vendor") and vendor:
                        _devices[ip]["vendor"] = vendor
                        changed = True
                    if not d.get("learned_from"):
                        _devices[ip]["learned_from"] = name
                        changed = True
                    if meraki_dev_name and not d.get("name"):
                        _devices[ip]["name"] = meraki_dev_name
                        changed = True
                    if meraki_online is not None:
                        new_ms = "online" if meraki_online else "offline"
                        if d.get("meraki_status") != new_ms:
                            _devices[ip]["meraki_status"] = new_ms
                            changed = True
                    if meraki_product and not d.get("meraki_product"):
                        _devices[ip]["meraki_product"] = meraki_product
                        changed = True
        if changed:
            _save_devices()
    return new_count

def _snmp_poller_loop() -> None:
    while True:
        try:
            _poll_snmp_devices()
        except Exception as e:
            log.exception("SNMP poll error: %s", e)
        time.sleep(300)

# ---------------------------------------------------------------------------
# Meraki Dashboard API
# ---------------------------------------------------------------------------
_MERAKI_API_BASE = "https://api.meraki.com/api/v1"

def _meraki_api_get(path: str, api_key: str, params: dict | None = None) -> list | dict | None:
    try:
        resp = requests.get(
            f"{_MERAKI_API_BASE}{path}",
            headers={"X-Cisco-Meraki-API-Key": api_key, "Accept": "application/json"},
            params=params or {},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        log.warning("Meraki API %s → %d: %s", path, resp.status_code, resp.text[:200])
    except Exception as e:
        log.warning("Meraki API %s failed: %s", path, e)
    return None

def _poll_meraki_api_clients() -> int:
    """Fetch clients from Meraki Dashboard API; enrich _devices with MAC/vendor/hostname."""
    key     = MERAKI_API_KEY
    net_id  = MERAKI_NETWORK_ID
    if not key or not net_id:
        return 0
    clients = _meraki_api_get(f"/networks/{net_id}/clients", key, {"timespan": 86400, "perPage": 1000})
    if not clients:
        return 0
    updated = 0
    for c in clients:
        ip  = c.get("ip") or ""
        mac = (c.get("mac") or "").lower()
        if not ip or not mac:
            continue
        vendor   = c.get("manufacturer") or ""
        hostname = c.get("description") or ""
        online   = (c.get("status") or "").lower() == "online"
        with _devices_lock:
            if ip not in _devices:
                _devices[ip] = {
                    "ip": ip, "mac": mac, "vendor": vendor,
                    "hostname": hostname, "name": "",
                    "learned_from": "Meraki API",
                    "meraki_status": "online" if online else "offline",
                    "meraki_product": "",
                    "monitored": False, "alert_mode": "default", "status": "unknown",
                    "last_seen": None, "ping_latency_ms": None,
                    "ports": [], "port_status": {},
                }
                log.info("Meraki API discovered %s — %s (%s)", ip, mac, vendor or "unknown")
                updated += 1
            else:
                d = _devices[ip]
                changed = False
                if mac and not d.get("mac"):
                    _devices[ip]["mac"] = mac;     changed = True
                if vendor and not d.get("vendor"):
                    _devices[ip]["vendor"] = vendor; changed = True
                if hostname and not d.get("hostname"):
                    _devices[ip]["hostname"] = hostname; changed = True
                ms = "online" if online else "offline"
                if d.get("meraki_status") != ms:
                    _devices[ip]["meraki_status"] = ms; changed = True
                if not d.get("learned_from"):
                    _devices[ip]["learned_from"] = "Meraki API"; changed = True
                if changed:
                    updated += 1
        _save_devices()
    log.info("Meraki API: %d clients, %d updated", len(clients), updated)
    return updated

def _meraki_api_poller_loop() -> None:
    while True:
        try:
            if MERAKI_API_KEY and MERAKI_NETWORK_ID:
                _poll_meraki_api_clients()
        except Exception as e:
            log.exception("Meraki API poll error: %s", e)
        time.sleep(MERAKI_POLL_INTERVAL)

# ---------------------------------------------------------------------------
# Runtime config overlay (persisted to disk, overrides env vars at runtime)
# ---------------------------------------------------------------------------
_CONFIG_PATH = os.environ.get("CONFIG_PATH", "/data/monitor_config.json")
_CONFIG_FIELDS = {
    # Home Assistant connection
    "ha_url":             {"label": "Home Assistant URL",              "default": HA_URL},
    "ha_token":           {"label": "HA long-lived access token",      "default": HA_TOKEN, "secret": True},
    "notify_service":     {"label": "Push notify service",             "default": NOTIFY_SERVICE},
    "smtp_host":         {"label": "SMTP host",           "default": SMTP_HOST},
    "smtp_port":         {"label": "SMTP port",           "default": str(SMTP_PORT)},
    "smtp_user":         {"label": "SMTP user",           "default": SMTP_USER},
    "smtp_pass":         {"label": "SMTP password",       "default": SMTP_PASS, "secret": True},
    "email_from":        {"label": "Email from",          "default": EMAIL_FROM},
    "email_from_name":   {"label": "Email from name",     "default": EMAIL_FROM_NAME},
    "email_to":          {"label": "Email to",            "default": EMAIL_TO},
    "alert_cooldown":         {"label": "Alert cooldown (s)",              "default": str(ALERT_COOLDOWN)},
    "push_alerts_enabled":    {"label": "Push alerts enabled",             "default": "true"},
    "push_critical":          {"label": "Send push as critical alert",     "default": "true"},
    "email_alerts_enabled":   {"label": "Email alerts enabled",            "default": "false"},
    "alert_title":            {"label": "Notification title prefix",       "default": "Farol"},
    "notify_recovery":        {"label": "Notify on recovery",              "default": "false"},
    # Service monitor knobs
    "zwave_update_entity":    {"label": "Z-Wave update entity",            "default": "update.z_wave_js_ui_update"},
    "zwave_integration":      {"label": "Z-Wave HA integration domain",    "default": "zwave_js"},
    "z2m_mqtt_prefix":        {"label": "Z2M MQTT prefix",                 "default": "zigbee2mqtt"},
    "z2m_health_entity":      {"label": "Z2M bridge health entity",        "default": "binary_sensor.zigbee2mqtt_bridge_connection_state"},
    "z2m_edge_mqtt_prefix":   {"label": "Z2M Edge MQTT prefix",            "default": "zigbee2mqtt2"},
    "z2m_edge_health_entity": {"label": "Z2M Edge bridge health entity",   "default": "binary_sensor.zigbee2mqtt_bridge_connection_state_2"},
    "mqtt_probe_host":        {"label": "Mosquitto probe host",            "default": HA_URL.split("://")[-1].split(":")[0]},
    "mqtt_probe_port":        {"label": "Mosquitto probe port",            "default": "1883"},
    # Meraki Dashboard API
    "meraki_api_key":         {"label": "Meraki API key",                  "default": "", "secret": True},
    "meraki_network_id":      {"label": "Meraki network ID",               "default": ""},
    # Network scan
    "scan_ports":             {"label": "Port scan list (comma-separated)", "default": "22,80,443,8080,8123,1883,8883"},
    "snmp_community":         {"label": "SNMP community string",            "default": "public"},
    # Polling intervals
    "poll_interval":          {"label": "Device ping interval (s)",         "default": str(POLL_INTERVAL)},
    "ha_poll_interval":       {"label": "HA add-on poll interval (s)",      "default": str(HA_POLL_INTERVAL)},
    "meraki_poll_interval":   {"label": "Meraki API poll interval (s)",     "default": str(MERAKI_POLL_INTERVAL)},
    # Sync
    "peer_url":               {"label": "Peer instance URL",               "default": ""},
    "alert_role":             {"label": "Alert role",                      "default": "standalone"},
    "auto_sync_peer":         {"label": "Auto-sync to peer on change",     "default": "false"},
}

def _load_config() -> dict:
    try:
        with open(_CONFIG_PATH) as fh:
            return json.load(fh)
    except Exception:
        return {}

def _save_config(data: dict) -> None:
    try:
        _atomic_write(_CONFIG_PATH, data)
    except Exception as e:
        log.error("Failed to save config: %s", e)

push_alerts_enabled:  bool = True
push_critical:        bool = True
email_alerts_enabled: bool = False
ALERT_TITLE:          str  = "Farol"
notify_recovery:      bool = False
MERAKI_API_KEY:       str  = ""
MERAKI_NETWORK_ID:    str  = ""
PEER_URL:             str  = ""
ALERT_ROLE:           str  = "standalone"  # standalone | primary | secondary
AUTO_SYNC_PEER:       bool = False
SNMP_COMMUNITY:       str  = "public"

_peer_reachable:      bool = True   # updated by _peer_health_loop
_peer_fail_streak:    int  = 0
_peer_ok_streak:      int  = 0

def _apply_config(data: dict) -> None:
    global HA_URL, HA_TOKEN
    global NOTIFY_SERVICE, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
    global EMAIL_FROM, EMAIL_FROM_NAME, EMAIL_TO, ALERT_COOLDOWN, push_alerts_enabled, push_critical, email_alerts_enabled
    global ALERT_TITLE, notify_recovery, MERAKI_API_KEY, MERAKI_NETWORK_ID, SCAN_PORTS, PEER_URL, ALERT_ROLE, AUTO_SYNC_PEER, SNMP_COMMUNITY
    global POLL_INTERVAL, HA_POLL_INTERVAL, MERAKI_POLL_INTERVAL
    if "ha_url"               in data: HA_URL               = data["ha_url"]       or HA_URL
    if "ha_token"             in data: HA_TOKEN             = data["ha_token"]     or HA_TOKEN
    if "notify_service"       in data: NOTIFY_SERVICE        = data["notify_service"]
    if "smtp_host"            in data: SMTP_HOST             = data["smtp_host"]
    if "smtp_port"            in data: SMTP_PORT             = int(data["smtp_port"] or 587)
    if "smtp_user"            in data: SMTP_USER             = data["smtp_user"]
    if "smtp_pass"            in data: SMTP_PASS             = data["smtp_pass"]
    if "email_from"           in data: EMAIL_FROM            = data["email_from"]
    if "email_from_name"      in data: EMAIL_FROM_NAME       = data["email_from_name"]
    if "email_to"             in data: EMAIL_TO              = data["email_to"]
    if "alert_cooldown"       in data: ALERT_COOLDOWN        = int(data["alert_cooldown"] or 300)
    if "push_alerts_enabled"  in data: push_alerts_enabled   = str(data["push_alerts_enabled"]).lower() in ("true", "1", "yes")
    if "push_critical"        in data: push_critical         = str(data["push_critical"]).lower() in ("true", "1", "yes")
    if "email_alerts_enabled" in data: email_alerts_enabled  = str(data["email_alerts_enabled"]).lower() in ("true", "1", "yes")
    if "alert_title"          in data: ALERT_TITLE           = data["alert_title"] or "Farol"
    if "notify_recovery"      in data: notify_recovery       = str(data["notify_recovery"]).lower() in ("true", "1", "yes")
    if "zwave_update_entity"    in data:
        ADDON_CONFIG["Z-Wave JS UI"]["update_entity"]   = data["zwave_update_entity"] or "update.z_wave_js_ui_update"
    if "zwave_integration"      in data:
        ADDON_CONFIG["Z-Wave JS UI"]["integration"]     = data["zwave_integration"] or "zwave_js"
    if "z2m_mqtt_prefix"        in data:
        ADDON_CONFIG["Zigbee2MQTT"]["mqtt_prefix"]      = data["z2m_mqtt_prefix"] or "zigbee2mqtt"
    if "z2m_health_entity"      in data:
        ADDON_CONFIG["Zigbee2MQTT"]["health_entity"]    = data["z2m_health_entity"] or None
    if "z2m_edge_mqtt_prefix"   in data:
        ADDON_CONFIG["Zigbee2MQTT Edge"]["mqtt_prefix"] = data["z2m_edge_mqtt_prefix"] or "zigbee2mqtt2"
    if "z2m_edge_health_entity" in data:
        ADDON_CONFIG["Zigbee2MQTT Edge"]["health_entity"] = data["z2m_edge_health_entity"] or None
    if "mqtt_probe_host"        in data:
        ADDON_CONFIG["Mosquitto Broker"]["health_port"]["host"] = data["mqtt_probe_host"] or "192.168.0.20"
    if "mqtt_probe_port"        in data:
        ADDON_CONFIG["Mosquitto Broker"]["health_port"]["port"] = int(data["mqtt_probe_port"] or 1883)
    if "meraki_api_key"         in data: MERAKI_API_KEY     = data["meraki_api_key"]    or ""
    if "meraki_network_id"      in data: MERAKI_NETWORK_ID  = data["meraki_network_id"] or ""
    if "scan_ports"             in data: SCAN_PORTS             = data["scan_ports"]             or ""
    if "poll_interval"          in data: POLL_INTERVAL          = int(data["poll_interval"]        or 30)
    if "ha_poll_interval"       in data: HA_POLL_INTERVAL       = int(data["ha_poll_interval"]     or 30)
    if "meraki_poll_interval"   in data: MERAKI_POLL_INTERVAL   = int(data["meraki_poll_interval"] or 300)
    if "peer_url"               in data: PEER_URL               = data["peer_url"]                 or ""
    if "alert_role"             in data: ALERT_ROLE             = data["alert_role"]               or "standalone"
    if "auto_sync_peer"         in data: AUTO_SYNC_PEER         = str(data["auto_sync_peer"]).lower() in ("true", "1", "yes")
    if "snmp_community"         in data: SNMP_COMMUNITY         = data["snmp_community"] or "public"

# ---------------------------------------------------------------------------
# Home Assistant API helpers
# ---------------------------------------------------------------------------
def ha_headers():
    return {
        "Authorization": f"Bearer {HA_TOKEN}",
        "Content-Type": "application/json",
    }


def ha_get(path: str, timeout: int = 10):
    """GET from the HA REST API."""
    url = f"{HA_URL}/api/{path}"
    resp = requests.get(url, headers=ha_headers(), timeout=timeout)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Monitoring checks
# ---------------------------------------------------------------------------

# Services to monitor: update entity for version, integration domain for live state
ADDON_CONFIG = {
    "Z-Wave JS UI": {
        "update_entity": "update.z_wave_js_ui_update",
        "integration": "zwave_js",
        "health_entity": None,
    },
    "Zigbee2MQTT": {
        "update_entity": "update.zigbee2mqtt_update",
        "integration": None,
        "health_entity": "binary_sensor.zigbee2mqtt_bridge_connection_state",
        "mqtt_prefix": os.environ.get("Z2M_MQTT_PREFIX", "zigbee2mqtt"),
    },
    "Zigbee2MQTT Edge": {
        "update_entity": "update.zigbee2mqtt_edge_update",
        "integration": None,
        "health_entity": "binary_sensor.zigbee2mqtt_bridge_connection_state_2",
        "mqtt_prefix": os.environ.get("Z2M_EDGE_MQTT_PREFIX", "zigbee2mqtt2"),
    },
    "Mosquitto Broker": {
        "update_entity": "update.mosquitto_broker_update",
        "integration": None,
        "health_entity": None,
        "health_port": {"host": "192.168.0.20", "port": 1883},
    },
}

_runtime_config = {k: meta["default"] for k, meta in _CONFIG_FIELDS.items()}
_runtime_config.update(_load_config())
_apply_config(_runtime_config)

# Cache of integration states from config entries
_integration_states: dict[str, str] = {}

# Cache of Z2M bridge/info payloads keyed by MQTT prefix
_z2m_bridge_cache: dict[str, tuple[float, dict]] = {}
_Z2M_BRIDGE_CACHE_TTL = 300  # seconds


def _fetch_z2m_bridge_info(mqtt_prefix: str) -> dict:
    """Connect to HA WebSocket and read the retained bridge/info payload for a Z2M instance."""
    ws_url = HA_URL.replace("http://", "ws://").replace("https://", "wss://") + "/api/websocket"
    ws = None
    try:
        ws = websocket.WebSocket()
        ws.connect(ws_url, timeout=10)
        ws.recv()  # auth_required
        ws.send(json.dumps({"type": "auth", "access_token": HA_TOKEN}))
        if json.loads(ws.recv()).get("type") != "auth_ok":
            return {}
        ws.send(json.dumps({"id": 1, "type": "mqtt/subscribe", "topic": f"{mqtt_prefix}/bridge/info"}))
        ws.settimeout(5)
        for _ in range(10):
            try:
                msg = json.loads(ws.recv())
                if msg.get("type") == "event" and msg.get("id") == 1:
                    payload = msg.get("event", {}).get("payload")
                    if payload:
                        return json.loads(payload)
            except websocket.WebSocketTimeoutException:
                break
    except Exception as exc:
        log.debug("Z2M bridge info(%s): %s", mqtt_prefix, exc)
    finally:
        if ws:
            try:
                ws.close()
            except Exception:
                pass
    return {}


def get_z2m_bridge_info(mqtt_prefix: str) -> dict:
    """Return cached Z2M bridge info, refreshing when stale."""
    now = time.time()
    cached = _z2m_bridge_cache.get(mqtt_prefix)
    if cached and now - cached[0] < _Z2M_BRIDGE_CACHE_TTL:
        return cached[1]
    info = _fetch_z2m_bridge_info(mqtt_prefix)
    _z2m_bridge_cache[mqtt_prefix] = (now, info)
    return info


def fmt_version(version: str) -> str:
    """Format version string, only adding 'v' prefix for numeric versions."""
    if not version or version == "?":
        return version
    if version[0].isdigit():
        return f"v{version}"
    return version


def refresh_integration_states():
    """Fetch all config entry states from HA and cache by domain."""
    global _integration_states
    try:
        entries = ha_get("config/config_entries/entry")
        states = {}
        for entry in entries:
            domain = entry.get("domain", "")
            state = entry.get("state", "unknown")
            # Keep the worst state per domain
            if domain not in states or state != "loaded":
                states[domain] = state
        _integration_states = states
    except Exception as e:
        log.warning("Could not fetch config entries: %s", e)


def check_addon(config: dict) -> dict:
    """Return add-on status using update entity + integration state."""
    update_entity = config["update_entity"]
    integration = config.get("integration")

    # 1. Get version info from the update entity
    version = "?"
    update_detail = ""
    try:
        data = ha_get(f"states/{update_entity}")
        state = data.get("state", "unknown")
        attrs = data.get("attributes", {})
        version = str(attrs.get("installed_version", "?"))
        latest = str(attrs.get("latest_available_version", "?"))
        if state == "on":
            update_detail = f" (update to {latest} available)"
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return {"status": "not_installed", "ok": True, "version": "", "detail": "Not installed (skipped)"}
        return {"status": "error", "ok": False, "version": "", "detail": str(e)}
    except Exception as e:
        return {"status": "error", "ok": False, "version": "", "detail": str(e)}

    # 2. Check integration state for actual liveness
    if integration:
        int_state = _integration_states.get(integration, "unknown")
        if int_state == "loaded":
            return {
                "status": "running",
                "ok": True,
                "version": version,
                "detail": f"{fmt_version(version)}{update_detail}",
            }
        else:
            return {
                "status": int_state,
                "ok": False,
                "version": version,
                "detail": f"{fmt_version(version)} — integration {int_state}",
            }

    # 3. Check health entity (e.g. Zigbee2MQTT bridge connection)
    health_entity = config.get("health_entity")
    if health_entity:
        try:
            h_data = ha_get(f"states/{health_entity}")
            h_state = h_data.get("state", "unknown")
            if h_state == "on":
                return {
                    "status": "running",
                    "ok": True,
                    "version": version,
                    "detail": f"{fmt_version(version)}{update_detail}",
                }
            else:
                return {
                    "status": "stopped",
                    "ok": False,
                    "version": version,
                    "detail": f"{fmt_version(version)} — bridge disconnected ({h_state})",
                }
        except Exception as e:
            return {"status": "error", "ok": False, "version": version, "detail": str(e)}

    # 4. TCP port probe (e.g. Mosquitto on 1883)
    health_port = config.get("health_port")
    if health_port:
        try:
            s = socket.create_connection(
                (health_port["host"], health_port["port"]), timeout=3
            )
            s.close()
            return {
                "status": "running",
                "ok": True,
                "version": version,
                "detail": f"{fmt_version(version)}{update_detail}",
            }
        except (ConnectionRefusedError, OSError, socket.timeout):
            return {
                "status": "stopped",
                "ok": False,
                "version": version,
                "detail": f"{fmt_version(version)} — port {health_port['port']} unreachable",
            }

    # 5. No integration, health entity, or port — rely on update entity availability
    return {
        "status": "running",
        "ok": True,
        "version": version,
        "detail": f"{fmt_version(version)}{update_detail}",
    }


def poll_once():
    """Run one monitoring cycle."""
    now = datetime.now(timezone.utc).isoformat()
    services = {}
    ha_reachable = False
    ha_version = ""

    # 1. Check HA reachability
    try:
        info = ha_get("")
        ha_reachable = True
        ha_version = info.get("version", "")
    except Exception as e:
        log.error("Cannot reach Home Assistant: %s", e)
        with state_lock:
            monitor_state.update({
                "last_poll": now,
                "ha_reachable": False,
                "services": {},
            })
        maybe_alert("home_assistant", "Home Assistant is unreachable", str(e))
        return

    # 2. Refresh integration states, then check add-ons
    refresh_integration_states()
    for name, config in ADDON_CONFIG.items():
        result = check_addon(config)

        # Enrich Z2M services with library versions from MQTT bridge/info
        mqtt_prefix = config.get("mqtt_prefix")
        if mqtt_prefix and result.get("status") not in ("not_installed",):
            info = get_z2m_bridge_info(mqtt_prefix)
            if info:
                versions: dict[str, str] = {}
                bridge_ver = info.get("version", "")
                commit = (info.get("commit") or "")
                if commit == "unknown":
                    commit = ""
                commit = commit[:7]
                if bridge_ver:
                    versions["main"] = bridge_ver
                if commit:
                    versions["commit"] = commit
                for vkey, field in [
                    ("herdsman", "zigbee_herdsman"),
                    ("converters", "zigbee_herdsman_converters"),
                    ("frontend", "frontend"),
                    ("node", "node"),
                ]:
                    d = info.get(field) or {}
                    if isinstance(d, dict) and d.get("version"):
                        versions[vkey] = d["version"]
                if versions:
                    result["versions"] = versions
                    v = bridge_ver or result.get("version", "?")
                    if v and v[0].isdigit():
                        v = f"v{v}"
                    new_detail = v + (f" · {commit}" if commit else "")
                    orig = result.get("detail", "")
                    for marker in [" (update to", " — bridge disconnected", " — port", " — integration"]:
                        idx = orig.find(marker)
                        if idx >= 0:
                            new_detail += orig[idx:]
                            break
                    result["detail"] = new_detail

        services[name] = result
        if not result["ok"] and result["status"] != "not_installed":
            maybe_alert(f"addon_{name}", f"{name} is DOWN", result["detail"])
            log.warning("Add-on %s: %s", name, result["detail"])

    # 3. Update shared state
    with state_lock:
        monitor_state.update({
            "last_poll": now,
            "ha_reachable": ha_reachable,
            "ha_version": ha_version,
            "services": services,
        })
    log.info("Poll complete — HA reachable, %d add-ons checked", len(services))


# ---------------------------------------------------------------------------
# Alerts — via Home Assistant companion app push notifications
# ---------------------------------------------------------------------------
def send_push(subject: str, body: str, critical: bool | None = None) -> bool:
    """Send a push notification via the HA companion app. Returns True on success."""
    try:
        service_parts = NOTIFY_SERVICE.split(".", 1)
        if len(service_parts) != 2:
            log.error("Invalid NOTIFY_SERVICE: %s", NOTIFY_SERVICE)
            return False
        domain, service = service_parts

        use_critical = push_critical if critical is None else critical
        url = f"{HA_URL}/api/services/{domain}/{service}"
        push_data: dict = {"group": "farol"}
        if use_critical:
            push_data["sound"] = {"name": "default", "critical": 1, "volume": 0.8}
        payload = {
            "title": f"{ALERT_TITLE}: {subject}",
            "message": body,
            "data": {
                "push": push_data,
                "url": "/config/dashboard",
                "group": "farol",
            },
        }
        resp = requests.post(url, headers=ha_headers(), json=payload, timeout=10)
        resp.raise_for_status()
        log.info("Push notification sent (%s): %s", "critical" if use_critical else "normal", subject)
        return True
    except Exception as e:
        log.error("Failed to send push: %s", e)
        return False


def _deliver_alert(subject: str, detail: str, do_push: bool, do_email: bool, critical):
    """Attempt push; fall back to email if push fails and email is available."""
    push_ok = False
    if do_push:
        push_ok = send_push(subject, detail, critical)
    if do_email or (do_push and not push_ok):
        if not push_ok and do_push:
            log.warning("Push failed — falling back to email for: %s", subject)
        send_email(subject, detail)


def send_email(subject: str, body: str):
    if not SMTP_HOST or not EMAIL_TO:
        log.warning("Email alert skipped — SMTP not configured")
        return
    try:
        is_recovery = any(w in subject.lower() for w in ("back online", "recovery", "recovered", "open"))
        accent      = "#4caf50" if is_recovery else "#db4437"
        icon        = "✅" if is_recovery else "🔴"
        timestamp   = datetime.now().strftime("%d %b %Y, %H:%M:%S")
        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:32px 0;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1);">
        <tr><td style="background:{accent};padding:20px 32px;">
          <p style="margin:0;color:#fff;font-size:13px;opacity:.85;">{ALERT_TITLE}</p>
          <h1 style="margin:6px 0 0;color:#fff;font-size:22px;font-weight:600;">{icon} {subject}</h1>
        </td></tr>
        <tr><td style="padding:28px 32px;">
          <p style="margin:0 0 8px;font-size:12px;color:#999;text-transform:uppercase;letter-spacing:.5px;">Detail</p>
          <p style="margin:0;font-size:15px;color:#333;line-height:1.6;background:#f8f8f8;border-left:3px solid {accent};padding:12px 16px;border-radius:0 4px 4px 0;">{body}</p>
        </td></tr>
        <tr><td style="padding:0 32px 28px;">
          <p style="margin:0;font-size:12px;color:#aaa;">{timestamp}</p>
        </td></tr>
        <tr><td style="background:#f8f8f8;padding:16px 32px;border-top:1px solid #eee;">
          <p style="margin:0;font-size:12px;color:#aaa;">Sent by <strong style="color:#666;">{ALERT_TITLE}</strong> — Farol</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""
        plain = f"{ALERT_TITLE}: {subject}\n\n{body}\n\n{timestamp}"

        msg = MIMEMultipart("alternative")
        msg["From"]    = formataddr((EMAIL_FROM_NAME, EMAIL_FROM or SMTP_USER))
        msg["To"]      = EMAIL_TO
        msg["Subject"] = f"{ALERT_TITLE}: {subject}"
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(msg["From"], [EMAIL_TO], msg.as_string())
        log.info("Email alert sent: %s", subject)
    except Exception as e:
        log.error("Failed to send email alert: %s", e)


def maybe_alert(key: str, subject: str, detail: str, mode: str | None = None):
    """Send alert if cooldown has elapsed. mode overrides global push/email settings.
    mode values: 'default', 'push_critical', 'push_normal', 'email', 'none'."""
    if not alerts_enabled:
        return
    if ALERT_ROLE == "secondary" and _peer_reachable:
        log.debug("Alert suppressed (secondary, peer reachable): %s", subject)
        return
    now = time.time()
    last = alert_history.get(key, 0)
    if now - last < ALERT_COOLDOWN:
        return
    alert_history[key] = now
    if not mode or mode == "default":
        do_push    = push_alerts_enabled
        do_email   = email_alerts_enabled
        critical   = None  # use global push_critical
    elif mode == "push_critical":
        do_push, do_email, critical = True, False, True
    elif mode == "push_normal":
        do_push, do_email, critical = True, False, False
    elif mode == "email":
        do_push, do_email, critical = False, True, False
    else:  # "none" or unknown
        return
    if key.endswith("_recovery"):
        _queue_recovery_alert(subject, detail, do_push, do_email, critical)
    else:
        threading.Thread(target=_deliver_alert, args=(subject, detail, do_push, do_email, critical), daemon=True).start()


# ---------------------------------------------------------------------------
# Recovery alert consolidation — batch recoveries within a short window
# ---------------------------------------------------------------------------
_recovery_queue:  list  = []
_recovery_lock         = threading.Lock()
_recovery_timer        = None
RECOVERY_BATCH_WINDOW  = 20  # seconds to collect recoveries before sending one email


def _queue_recovery_alert(subject: str, detail: str, do_push: bool, do_email: bool, critical):
    global _recovery_timer
    with _recovery_lock:
        _recovery_queue.append({"subject": subject, "detail": detail,
                                 "do_push": do_push, "do_email": do_email, "critical": critical})
        if _recovery_timer:
            _recovery_timer.cancel()
        _recovery_timer = threading.Timer(RECOVERY_BATCH_WINDOW, _flush_recovery_alerts)
        _recovery_timer.daemon = True
        _recovery_timer.start()


def _flush_recovery_alerts():
    global _recovery_timer
    with _recovery_lock:
        items = list(_recovery_queue)
        _recovery_queue.clear()
        _recovery_timer = None
    if not items:
        return
    if len(items) == 1:
        i = items[0]
        threading.Thread(target=_deliver_alert,
                         args=(i["subject"], i["detail"], i["do_push"], i["do_email"], i["critical"]),
                         daemon=True).start()
        return
    do_push  = any(i["do_push"]  for i in items)
    do_email = any(i["do_email"] for i in items)
    critical = any(i["critical"] for i in items)
    subject  = f"{len(items)} services back online"
    detail   = "\n".join(f"• {i['subject']}: {i['detail']}" for i in items)
    threading.Thread(target=_deliver_alert, args=(subject, detail, do_push, do_email, critical), daemon=True).start()


# ---------------------------------------------------------------------------
# Auto-sync to peer
# ---------------------------------------------------------------------------
def _trigger_auto_sync():
    if not AUTO_SYNC_PEER or not PEER_URL:
        return
    def _push():
        try:
            bundle = _build_sync_bundle()
            r = requests.post(f"{PEER_URL.rstrip('/')}/api/sync/import", json=bundle, timeout=15)
            r.raise_for_status()
            log.info("Auto-sync: pushed to peer %s", PEER_URL)
        except Exception as e:
            log.warning("Auto-sync push failed: %s", e)
    threading.Thread(target=_push, daemon=True).start()


# ---------------------------------------------------------------------------
# Background poller
# ---------------------------------------------------------------------------
def _ha_poller_loop():
    while True:
        try:
            poll_once()
        except Exception as e:
            log.exception("HA poll error: %s", e)
        time.sleep(HA_POLL_INTERVAL)

def _device_ping_loop():
    while True:
        try:
            _ping_monitored()
        except Exception as e:
            log.exception("Ping monitoring error: %s", e)
        time.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    with state_lock:
        state = json.loads(json.dumps(monitor_state))
    return render_template("index.html", state=state, poll_interval=POLL_INTERVAL,
                           version=VERSION, node_role=ALERT_ROLE)


@app.route("/api/status")
def api_status():
    with state_lock:
        state = json.loads(json.dumps(monitor_state))
    return jsonify(state)


@app.route("/api/health")
def api_health():
    with state_lock:
        reachable = monitor_state["ha_reachable"]
    return jsonify({"healthy": reachable}), 200 if reachable else 503


@app.route("/api/devices")
def api_devices():
    with _devices_lock:
        devs = sorted(_devices.values(), key=lambda d: [int(x) for x in d["ip"].split(".")])
    result = []
    for d in devs:
        dev = dict(d)
        if dev.get("monitored"):
            dev["uptime"] = _uptime_stats(d["ip"])
        result.append(dev)
    return jsonify(result)


@app.route("/api/devices/<ip>", methods=["GET"])
def api_device_get(ip):
    with _devices_lock:
        if ip not in _devices:
            return jsonify({"error": "not found"}), 404
        dev = dict(_devices[ip])
    dev["uptime"]  = _uptime_stats(ip)
    dev["history"] = _history_buckets(ip)
    return jsonify(dev)


@app.route("/api/devices/<ip>", methods=["PATCH"])
def api_device_patch(ip):
    with _devices_lock:
        if ip not in _devices:
            return jsonify({"error": "not found"}), 404
        for k in ("name", "monitored", "ports", "alert_mode"):
            if k in (request.json or {}):
                _devices[ip][k] = request.json[k]
        _save_devices()
        _trigger_auto_sync()
        return jsonify(_devices[ip])


@app.route("/api/devices/<ip>", methods=["DELETE"])
def api_device_delete(ip):
    with _devices_lock:
        _devices.pop(ip, None)
        _save_devices()
    _trigger_auto_sync()
    return jsonify({"ok": True})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if _scan_status.get("state") == "running":
        return jsonify({"status": "error", "message": "Scan already running"}), 409
    network = (request.json or {}).get("network") or _local_network()
    threading.Thread(target=_do_scan, args=(network,), daemon=True).start()
    return jsonify({"status": "started", "network": network})


@app.route("/api/scan/status")
def api_scan_status():
    return jsonify({**_scan_status, "network": _local_network()})


@app.route("/api/snmp_devices", methods=["GET", "POST"])
def api_snmp_devices():
    global _snmp_devices
    if request.method == "POST":
        data = request.json or {}
        if not data.get("host"):
            return jsonify({"ok": False, "error": "host required"}), 400
        device = {
            "id":        str(uuid.uuid4()),
            "name":      data.get("name") or data["host"],
            "host":      data["host"],
            "community": data.get("community") or "public",
            "port":      int(data.get("port") or 161),
            "version":   data.get("version") or "2c",
            "type":      data.get("type") or "switch",
            "enabled":   True,
        }
        with _snmp_lock:
            _snmp_devices.append(device)
            _save_snmp_devices()
        return jsonify(device)
    with _snmp_lock:
        return jsonify(list(_snmp_devices))


@app.route("/api/snmp_devices/<device_id>", methods=["PUT", "DELETE"])
def api_snmp_device(device_id):
    global _snmp_devices
    if request.method == "DELETE":
        with _snmp_lock:
            _snmp_devices = [d for d in _snmp_devices if d["id"] != device_id]
            _save_snmp_devices()
        return jsonify({"ok": True})
    # PUT — update existing device
    data = request.json or {}
    with _snmp_lock:
        for d in _snmp_devices:
            if d["id"] == device_id:
                d["name"]      = data.get("name")      or d["name"]
                d["host"]      = data.get("host")      or d["host"]
                d["community"] = data.get("community") or d["community"]
                d["port"]      = int(data.get("port") or 161)
                d["version"]   = data.get("version")   or d["version"]
                d["type"]      = data.get("type")      or d["type"]
                _save_snmp_devices()
                return jsonify(d)
    return jsonify({"ok": False, "error": "not found"}), 404


@app.route("/api/snmp_test", methods=["POST"])
def api_snmp_test():
    data = request.json or {}
    host      = data.get("host", "")
    community = data.get("community", "public")
    dev_type  = data.get("type", "")
    port      = int(data.get("port", 161) or 161)
    if not host:
        return jsonify({"ok": False, "error": "host required"}), 400
    rows = _snmpwalk(host, community, "1.3.6.1.2.1.1.1.0", timeout=5, port=port)
    if not rows:
        # Meraki MX may not respond to sysDescr but does respond to devTable
        if dev_type == "meraki":
            meraki_devs = _poll_meraki_devtable(host, community, port=port)
            if meraki_devs:
                names = [d.get("name","?") for d in meraki_devs.values()]
                return jsonify({"ok": True, "description": "Meraki Cloud Controller",
                                "arp_entries": 0, "bridge_macs": 0,
                                "meraki_devices": len(meraki_devs),
                                "meraki_names": ", ".join(names[:5])})
        return jsonify({"ok": False, "error": f"No SNMP response from {host}:{port} (check host, community string, and that SNMP is enabled)"})
    descr = rows[0][1].replace("STRING:", "").strip().strip('"')
    if dev_type == "meraki":
        # Meraki MX blocks standard ARP/bridge OIDs — go straight to devTable
        meraki_devs = _poll_meraki_devtable(host, community, port=port)
        names = ", ".join(d.get("name", "?") for d in meraki_devs.values())
        return jsonify({"ok": True, "description": descr,
                        "meraki_devices": len(meraki_devs),
                        "meraki_names": names or "none found"})
    arp    = _snmpwalk(host, community, "1.3.6.1.2.1.4.22.1.2", timeout=5, port=port)
    if not arp:
        arp = [r for r in _snmpwalk(host, community, "1.3.6.1.2.1.4.35.1.4", timeout=5, port=port)
               if len(r[0].split(".")) >= 6 and r[0].split(".")[-6] == "1" and r[0].split(".")[-5] == "4"]
    bridge = _snmpwalk(host, community, "1.3.6.1.2.1.17.4.3.1.1", timeout=5, port=port)
    return jsonify({"ok": True, "description": descr, "arp_entries": len(arp), "bridge_macs": len(bridge)})


@app.route("/api/snmp_poll", methods=["POST"])
def api_snmp_poll():
    with _snmp_lock:
        if not _snmp_devices:
            return jsonify({"ok": False, "error": "No SNMP devices configured"}), 400
    threading.Thread(target=_poll_snmp_devices, daemon=True).start()
    return jsonify({"ok": True, "message": "Poll started"})


@app.route("/api/meraki_api/networks", methods=["POST"])
def api_meraki_networks():
    data   = request.json or {}
    key    = data.get("api_key") or MERAKI_API_KEY
    org_id = data.get("org_id", "")
    if not key:
        return jsonify({"ok": False, "error": "API key required"}), 400
    if org_id:
        nets = _meraki_api_get(f"/organizations/{org_id}/networks", key)
        if nets is None:
            return jsonify({"ok": False, "error": "Failed to fetch networks — check key and org ID"}), 400
    else:
        orgs = _meraki_api_get("/organizations", key)
        if orgs is None:
            return jsonify({"ok": False, "error": "API key rejected (401) — verify the key in your Meraki dashboard under My Profile → API access"}), 401
        if not orgs:
            return jsonify({"ok": False, "error": "No organisations found for this API key"}), 400
        nets = []
        for org in orgs:
            n = _meraki_api_get(f"/organizations/{org['id']}/networks", key)
            if n:
                for net in n:
                    net["_org_name"] = org["name"]
                nets.extend(n)
    return jsonify({"ok": True, "networks": [{"id": n["id"], "name": n["name"],
                                               "org": n.get("_org_name", "")} for n in nets]})


@app.route("/api/meraki_api/test", methods=["POST"])
def api_meraki_api_test():
    data   = request.json or {}
    key    = data.get("api_key") or MERAKI_API_KEY
    net_id = data.get("network_id") or MERAKI_NETWORK_ID
    if not key:
        return jsonify({"ok": False, "error": "API key required"}), 400
    if not net_id:
        return jsonify({"ok": False, "error": "Network ID required"}), 400
    clients = _meraki_api_get(f"/networks/{net_id}/clients", key, {"timespan": 3600, "perPage": 5})
    if clients is None:
        return jsonify({"ok": False, "error": "API request failed — check key and network ID"}), 400
    net_info = _meraki_api_get(f"/networks/{net_id}", key)
    net_name = net_info.get("name", net_id) if net_info else net_id
    return jsonify({"ok": True, "network_name": net_name, "client_sample": len(clients)})


@app.route("/api/meraki_api/poll", methods=["POST"])
def api_meraki_api_poll():
    if not MERAKI_API_KEY or not MERAKI_NETWORK_ID:
        return jsonify({"ok": False, "error": "Meraki API not configured"}), 400
    threading.Thread(target=_poll_meraki_api_clients, daemon=True).start()
    return jsonify({"ok": True, "message": "Poll started"})


def _peer_health_loop() -> None:
    """Periodically check primary health; flip _peer_reachable for secondary failover."""
    global _peer_reachable, _peer_fail_streak, _peer_ok_streak
    while True:
        time.sleep(30)
        if ALERT_ROLE != "secondary" or not PEER_URL:
            # Not in secondary mode — reset to reachable so guards don't block
            if not _peer_reachable:
                _peer_reachable = True
                _peer_fail_streak = 0
                _peer_ok_streak = 0
            continue
        try:
            resp = requests.get(f"{PEER_URL.rstrip('/')}/api/health", timeout=5)
            if resp.status_code == 200:
                _peer_fail_streak = 0
                _peer_ok_streak += 1
                if not _peer_reachable and _peer_ok_streak >= 2:
                    _peer_reachable = True
                    log.info("Primary peer %s recovered — secondary resuming standby", PEER_URL)
            else:
                raise RuntimeError(f"HTTP {resp.status_code}")
        except Exception as e:
            _peer_ok_streak = 0
            _peer_fail_streak += 1
            if _peer_reachable and _peer_fail_streak >= 2:
                _peer_reachable = False
                log.warning("Primary peer %s unreachable (%d checks) — secondary taking over alerts", PEER_URL, _peer_fail_streak)


def _primary_peer_check_loop() -> None:
    """Periodically ping the peer and probe its /api/health for display on the primary dashboard."""
    from urllib.parse import urlparse
    while True:
        time.sleep(30)
        if ALERT_ROLE != "primary" or not PEER_URL:
            with state_lock:
                monitor_state["peer_status"] = {}
            continue
        try:
            ip = urlparse(PEER_URL).hostname or ""
            ping_ok, latency = (_ping_host(ip) if ip else (False, None))
            service_ok = False
            try:
                r = requests.get(f"{PEER_URL.rstrip('/')}/api/health", timeout=5)
                service_ok = r.status_code == 200
            except Exception:
                pass
            with state_lock:
                monitor_state["peer_status"] = {
                    "url":            PEER_URL,
                    "ip":             ip,
                    "ping_ok":        ping_ok,
                    "latency_ms":     round(latency, 1) if latency is not None else None,
                    "service_ok":     service_ok,
                }
        except Exception as e:
            log.debug("Primary peer check error: %s", e)


def _build_sync_bundle() -> dict:
    """Collect all syncable settings into a portable bundle."""
    with _devices_lock:
        device_settings = [
            {k: d[k] for k in ("ip", "name", "monitored", "ports", "alert_mode") if k in d}
            for d in _devices.values()
        ]
    with _snmp_lock:
        snmp = list(_snmp_devices)
    # Exclude instance-specific keys that must not propagate to the peer
    _SYNC_EXCLUDE = {"peer_url", "alert_role"}
    config_export = {k: v for k, v in _runtime_config.items() if k in _CONFIG_FIELDS and k not in _SYNC_EXCLUDE}
    return {"config": config_export, "snmp_devices": snmp, "devices": device_settings}


def _apply_sync_bundle(data: dict) -> dict:
    """Apply an imported sync bundle; return counts of imported items."""
    global _snmp_devices, _runtime_config
    counts: dict = {}
    cfg = data.get("config", {})
    if cfg:
        merged = {k: v for k, v in cfg.items() if k in _CONFIG_FIELDS and k not in {"peer_url", "alert_role"}}
        _runtime_config.update(merged)
        _save_config(_runtime_config)
        _apply_config(_runtime_config)
        counts["config"] = len(merged)
    snmp = data.get("snmp_devices")
    if snmp is not None:
        with _snmp_lock:
            _snmp_devices = snmp
            _save_snmp_devices()
        counts["snmp_devices"] = len(snmp)
    devices = data.get("devices", [])
    with _devices_lock:
        for d in devices:
            ip = d.get("ip")
            if not ip:
                continue
            if ip in _devices:
                for k in ("name", "monitored", "ports", "alert_mode"):
                    if k in d:
                        _devices[ip][k] = d[k]
            else:
                _devices[ip] = {
                    "ip": ip, "mac": "", "vendor": "", "hostname": "",
                    "name": d.get("name", ""), "monitored": d.get("monitored", False),
                    "alert_mode": d.get("alert_mode", "default"),
                    "status": "unknown", "last_seen": None, "ping_latency_ms": None,
                    "ports": d.get("ports", []), "port_status": {},
                }
        _save_devices()
    counts["devices"] = len(devices)
    return counts


@app.route("/api/sync/status")
def api_sync_status():
    with state_lock:
        peer_status = monitor_state.get("peer_status", {})
    return jsonify({
        "role":           ALERT_ROLE,
        "peer_url":       PEER_URL,
        "peer_reachable": _peer_reachable,
        "alerting":       ALERT_ROLE != "secondary" or not _peer_reachable,
        "peer_status":    peer_status,
    })


@app.route("/api/sync/export")
def api_sync_export():
    return jsonify(_build_sync_bundle())


@app.route("/api/sync/import", methods=["POST"])
def api_sync_import():
    counts = _apply_sync_bundle(request.json or {})
    log.info("Sync import applied: %s", counts)
    return jsonify({"ok": True, "imported": counts})


@app.route("/api/sync/push", methods=["POST"])
def api_sync_push():
    peer = ((request.json or {}).get("peer_url") or PEER_URL or "").rstrip("/")
    if not peer:
        return jsonify({"ok": False, "error": "Peer URL not configured"}), 400
    try:
        bundle = _build_sync_bundle()
        resp = requests.post(f"{peer}/api/sync/import", json=bundle, timeout=15)
        resp.raise_for_status()
        result = resp.json().get("imported", {})
        log.info("Sync push to %s: %s", peer, result)
        return jsonify({"ok": True, "peer": peer, "imported": result})
    except Exception as e:
        log.error("Sync push to %s failed: %s", peer, e)
        return jsonify({"ok": False, "error": str(e)}), 502


@app.route("/api/sync/pull", methods=["POST"])
def api_sync_pull():
    peer = ((request.json or {}).get("peer_url") or PEER_URL or "").rstrip("/")
    if not peer:
        return jsonify({"ok": False, "error": "Peer URL not configured"}), 400
    try:
        resp = requests.get(f"{peer}/api/sync/export", timeout=15)
        resp.raise_for_status()
        counts = _apply_sync_bundle(resp.json())
        log.info("Sync pull from %s: %s", peer, counts)
        return jsonify({"ok": True, "peer": peer, "imported": counts})
    except Exception as e:
        log.error("Sync pull from %s failed: %s", peer, e)
        return jsonify({"ok": False, "error": str(e)}), 502


@app.route("/api/update", methods=["POST"])
def api_update():
    """Rebuild image from /app-src and restart with preserved settings."""

    def _do_update():
        try:
            inspect = subprocess.run(
                ["docker", "inspect", "farol", "--format", "{{json .Config.Env}}"],
                capture_output=True, text=True, timeout=10,
            )
            if inspect.returncode != 0:
                log.error("Update: inspect failed: %s", inspect.stderr)
                return
            env_list = json.loads(inspect.stdout.strip())
            skip = ("PATH=", "HOSTNAME=", "HOME=", "PYTHONDONTWRITEBYTECODE=", "PYTHONUNBUFFERED=")
            env_lines = [e for e in env_list if not any(e.startswith(s) for s in skip)]
            with open("/app-src/container.env", "w") as fh:
                fh.write("\n".join(env_lines) + "\n")
            log.info("Update: saved %d env vars", len(env_lines))

            log.info("Update: building farol:latest ...")
            build = subprocess.run(
                ["docker", "build", "-t", "farol:latest", "/app-src"],
                capture_output=True, text=True, timeout=300,
            )
            if build.returncode != 0:
                log.error("Update: build failed:\n%s", build.stderr)
                return
            log.info("Update: build complete")

            restart_script = (
                "sleep 2 && "
                "docker stop farol; "
                "docker rm farol; "
                "docker run -d"
                " --name farol"
                " --restart unless-stopped"
                " -p 9099:9099"
                " -v /var/run/docker.sock:/var/run/docker.sock"
                " -v /usr/bin/docker:/usr/bin/docker:ro"
                " -v /mnt/user/appdata/farol:/app-src"
                " --env-file /app-src/container.env"
                " farol:latest"
            )
            r = subprocess.run(
                [
                    "docker", "run", "-d", "--rm",
                    "--name", "farol-updater",
                    "-v", "/var/run/docker.sock:/var/run/docker.sock",
                    "-v", "/usr/bin/docker:/usr/bin/docker:ro",
                    "-v", "/mnt/user/appdata/farol:/app-src",
                    "farol:latest",
                    "sh", "-c", restart_script,
                ],
                capture_output=True, text=True, timeout=30,
            )
            log.info("Update: helper launched (rc=%d)", r.returncode)
        except Exception as exc:
            log.error("Update: %s", exc)

    threading.Thread(target=_do_update, daemon=True).start()
    return jsonify({"status": "updating", "message": "Rebuilding... service restarts in ~60s."})


@app.route("/api/z2m_update_status")
def api_z2m_update_status():
    return jsonify(z2m_update_status)


@app.route("/api/alerts_enabled", methods=["GET", "POST"])
def api_alerts_enabled():
    global alerts_enabled
    if request.method == "POST":
        alerts_enabled = bool(request.json.get("enabled", True))
        _persist_alerts_enabled(alerts_enabled)
    return jsonify({"enabled": alerts_enabled})


@app.route("/config")
def config_page():
    fields = []
    for key, meta in _CONFIG_FIELDS.items():
        fields.append({
            "key": key,
            "label": meta["label"],
            "value": _runtime_config.get(key, meta["default"]),
            "secret": meta.get("secret", False),
        })
    return render_template("config.html", fields=fields)


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    global _runtime_config
    if request.method == "POST":
        data = {k: v for k, v in request.json.items() if k in _CONFIG_FIELDS}
        _runtime_config.update(data)
        _save_config(_runtime_config)
        _apply_config(_runtime_config)
        _trigger_auto_sync()
    safe = {k: ("••••••" if _CONFIG_FIELDS[k].get("secret") and v else v)
            for k, v in _runtime_config.items() if k in _CONFIG_FIELDS}
    return jsonify(safe)


@app.route("/logs")
def logs_page():
    return render_template("logs.html")


@app.route("/device/<ip>")
def device_page(ip):
    with _devices_lock:
        if ip not in _devices:
            return redirect("/")
    return render_template("device.html", ip=ip, version=VERSION)

@app.route("/api/logs")
def api_logs():
    n = min(int(request.args.get("n", 500)), _LOG_BUFFER_MAX)
    recs = _LOG_BUFFER[-n:]
    return jsonify({"records": recs, "verbose": _buf_handler.level == logging.DEBUG})


@app.route("/api/logs/level", methods=["POST"])
def api_logs_level():
    enabled = (request.json or {}).get("verbose", False)
    _set_verbose(enabled)
    log.info("Verbose logging %s", "enabled" if enabled else "disabled")
    return jsonify({"verbose": enabled})


@app.route("/api/test_push", methods=["POST"])
def api_test_push():
    try:
        send_push("Test notification", "Farol push notifications are working.")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/test_email", methods=["POST"])
def api_test_email():
    try:
        if not SMTP_HOST or not EMAIL_TO:
            return jsonify({"ok": False, "error": "SMTP host and Email to are required"})
        msg = MIMEMultipart()
        msg["From"] = EMAIL_FROM or SMTP_USER
        msg["To"] = EMAIL_TO
        msg["Subject"] = "Farol — test email"
        msg.attach(MIMEText("Farol email alerts are working.", "plain"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(msg["From"], [EMAIL_TO], msg.as_string())
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/z2m_backup")
def api_z2m_backup():
    backup_path = os.environ.get("Z2M_BACKUP_PATH", "/data/z2m_edge_backup.json")
    if not os.path.exists(backup_path):
        return jsonify({"error": "No backup found yet"}), 404
    with open(backup_path) as fh:
        return jsonify(json.load(fh))


@app.route("/api/update_z2m", methods=["POST"])
def api_update_z2m():
    """Uninstall Z2M Edge, refresh store, reinstall, restore config via HA WebSocket supervisor/api."""
    global z2m_update_status
    Z2M_EDGE_SLUG = os.environ.get("Z2M_EDGE_SLUG", "45df7312_zigbee2mqtt_edge")
    Z2M_EDGE_PORT = int(os.environ.get("Z2M_EDGE_PORT", "8486"))
    Z2M_BACKUP_PATH = os.environ.get("Z2M_BACKUP_PATH", "/data/z2m_edge_backup.json")

    def _set(state, message):
        global z2m_update_status
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = f"[{ts}] {message}"
        prev_log = z2m_update_status.get("log", [])
        z2m_update_status = {"state": state, "message": message, "log": prev_log + [entry]}
        log.info("Z2M update [%s]: %s", state, message)
        if state in ("error", "done"):
            _persist_z2m_status(z2m_update_status)

    def _dbg(msg):
        global z2m_update_status
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        prev = z2m_update_status.get("log", [])
        z2m_update_status = {**z2m_update_status, "log": prev + [entry]}
        log.info("Z2M dbg: %s", msg)

    def _ws_sup(method, endpoint, payload=None, timeout=60):
        """Open a fresh WebSocket, send one supervisor/api command, return result data."""
        ws_url = HA_URL.replace("http://", "ws://").replace("https://", "wss://") + "/api/websocket"
        _dbg(f"WS {method} {endpoint}" + (f" payload={json.dumps(payload)[:200]}" if payload else ""))
        ws = websocket.WebSocket()
        try:
            ws.connect(ws_url, timeout=30)
            ws.recv()  # auth_required
            ws.send(json.dumps({"type": "auth", "access_token": HA_TOKEN}))
            if json.loads(ws.recv()).get("type") != "auth_ok":
                raise RuntimeError("WebSocket auth failed")
            cmd = {"id": 1, "type": "supervisor/api", "method": method, "endpoint": endpoint}
            if payload is not None:
                cmd["data"] = payload
            ws.send(json.dumps(cmd))
            ws.settimeout(timeout)
            while True:
                raw = ws.recv()
                resp = json.loads(raw)
                _dbg(f"WS recv id={resp.get('id')} type={resp.get('type')} success={resp.get('success')} result_keys={list(resp.get('result', {}).keys()) if isinstance(resp.get('result'), dict) else resp.get('result')}")
                if resp.get("id") == 1 and resp.get("type") == "result":
                    if not resp.get("success"):
                        raise RuntimeError(
                            f"{method} {endpoint} failed: {resp.get('error') or resp}"
                        )
                    r = resp.get("result", {})
                    return r.get("data", r) if isinstance(r, dict) else r
        finally:
            try:
                ws.close()
            except Exception:
                pass

    def _do_update():
        import traceback
        try:
            # Step 1 — backup current options
            _set("running", "Backing up Z2M Edge config…")
            info = _ws_sup("GET", f"/addons/{Z2M_EDGE_SLUG}/info")
            saved_options = info.get("options", {})
            if not saved_options:
                raise RuntimeError(f"Could not read addon options — full info: {info}")
            _dbg(f"Addon state: {info.get('state')}, version: {info.get('version')}")
            _dbg(f"Options: {json.dumps(saved_options)}")
            try:
                os.makedirs(os.path.dirname(Z2M_BACKUP_PATH), exist_ok=True)
                with open(Z2M_BACKUP_PATH, "w") as fh:
                    json.dump({"timestamp": datetime.now(timezone.utc).isoformat(),
                               "slug": Z2M_EDGE_SLUG, "options": saved_options}, fh, indent=2)
                _dbg(f"Config backed up to {Z2M_BACKUP_PATH}")
            except Exception as be:
                _dbg(f"WARNING: could not write backup file: {be}")

            # Step 2 — uninstall
            _set("running", "Uninstalling Z2M Edge…")
            uninstall_result = _ws_sup("POST", f"/addons/{Z2M_EDGE_SLUG}/uninstall")
            _dbg(f"Uninstall result: {uninstall_result}")
            time.sleep(3)

            # Step 3 — refresh store; give repos time to fetch before install
            _set("running", "Refreshing add-on store…")
            reload_result = _ws_sup("POST", "/store/reload")
            _dbg(f"Store reload result: {reload_result}")
            _dbg("Waiting 30 s for store cache to warm…")
            time.sleep(30)

            # Step 4 — install latest; retry a few times in case store cache is still warming.
            # HA sometimes returns success=False with an empty message even when the install
            # actually succeeded asynchronously.  After any failure, probe the addon state
            # before deciding whether to retry.
            _set("running", "Installing latest Z2M Edge…")
            for install_attempt in range(3):
                try:
                    install_result = _ws_sup("POST", f"/store/addons/{Z2M_EDGE_SLUG}/install", timeout=300)
                    _dbg(f"Install result: {install_result}")
                    break
                except Exception as ie:
                    err_str = str(ie)
                    _dbg(f"Install attempt {install_attempt + 1} returned: {ie}")
                    # Check whether the addon is actually present now (HA async quirk)
                    try:
                        probe = _ws_sup("GET", f"/addons/{Z2M_EDGE_SLUG}/info")
                        _dbg(f"Post-install probe: state={probe.get('state')}, version={probe.get('version')}")
                        _dbg("Addon present — HA install quirk, continuing with config restore")
                        break
                    except Exception as pe:
                        _dbg(f"Post-install probe failed: {pe}")
                    if install_attempt < 2:
                        _set("running", f"Install attempt {install_attempt + 1} failed — retrying in 15 s…")
                        time.sleep(15)
                    else:
                        raise

            # Step 5 — poll addon state until it settles (up to 6 min, fresh WS each poll)
            # version=None means HA is still downloading; only break when version is populated.
            _set("running", "Waiting for install to complete…")
            for attempt in range(72):
                time.sleep(5)
                try:
                    chk = _ws_sup("GET", f"/addons/{Z2M_EDGE_SLUG}/info")
                    addon_state   = chk.get("state", "")
                    addon_version = chk.get("version")
                    _dbg(f"Poll {attempt + 1}: addon state={addon_state}, version={addon_version}")
                    if addon_state in ("stopped", "started", "running"):
                        break
                    if addon_state == "unknown" and addon_version:
                        break
                except Exception as e:
                    _dbg(f"Poll {attempt + 1} error: {e}")
                _set("running", f"Waiting for install… ({(attempt + 1) * 5}s)")
            else:
                raise RuntimeError("Timed out waiting for addon to install")

            # Step 6a — stop addon if it auto-started after install so options apply cleanly
            _set("running", "Stopping addon before restoring config…")
            try:
                chk = _ws_sup("GET", f"/addons/{Z2M_EDGE_SLUG}/info")
                addon_state_now = chk.get("state", "")
                _dbg(f"Pre-options state: {addon_state_now}")
                if addon_state_now in ("started", "running"):
                    _dbg("Addon is running — stopping before options restore")
                    _ws_sup("POST", f"/addons/{Z2M_EDGE_SLUG}/stop")
                    time.sleep(5)
                else:
                    _dbg("Addon already stopped — no need to stop")
            except Exception as e:
                _dbg(f"Stop-before-options error: {e} (continuing anyway)")

            # Step 6b — restore saved options; set network port binding, watchdog, sidebar
            _set("running", "Restoring config options…")
            options_payload: dict = {
                "options":       saved_options,
                "watchdog":      True,
                "ingress_panel": True,
            }
            if Z2M_EDGE_PORT:
                options_payload["network"] = {"8485/tcp": Z2M_EDGE_PORT}
            _dbg(f"Options payload: {json.dumps(options_payload)[:500]}")
            options_result = _ws_sup("POST", f"/addons/{Z2M_EDGE_SLUG}/options", options_payload)
            _dbg(f"Options result: {options_result}")

            # Step 7 — start (HA may return success=False with empty message even when it works)
            _set("running", "Starting Z2M Edge…")
            try:
                start_result = _ws_sup("POST", f"/addons/{Z2M_EDGE_SLUG}/start")
                _dbg(f"Start result: {start_result}")
            except Exception as se:
                _dbg(f"Start call error: {se} — probing addon state")
                time.sleep(5)
                probe = _ws_sup("GET", f"/addons/{Z2M_EDGE_SLUG}/info")
                probe_state = probe.get("state", "")
                _dbg(f"Post-start probe: state={probe_state}")
                if probe_state not in ("started", "running"):
                    raise

            # Step 8 — wait for bridge to reconnect
            _set("running", "Waiting for Z2M Edge bridge to come online…")
            for attempt in range(60):
                time.sleep(5)
                try:
                    data = ha_get("states/binary_sensor.zigbee2mqtt_bridge_connection_state_2")
                    bridge_state = data.get("state")
                    _dbg(f"Bridge poll {attempt + 1}: state={bridge_state}")
                    if bridge_state == "on":
                        _set("done", "Z2M Edge updated and reconnected!")
                        return
                except Exception as e:
                    _dbg(f"Bridge poll {attempt + 1} error: {e}")
                _set("running", f"Waiting for bridge… ({(attempt + 1) * 5}s)")

            _set("done", "Z2M Edge installed and started — bridge may still be connecting.")

        except Exception as exc:
            tb = traceback.format_exc()
            _dbg(f"EXCEPTION:\n{tb}")
            _set("error", f"Error: {exc}")

    if z2m_update_status.get("state") == "running":
        return jsonify({"status": "error", "message": "Update already in progress"}), 409
    z2m_update_status = {"state": "running", "message": "Starting…", "log": []}
    threading.Thread(target=_do_update, daemon=True).start()
    return jsonify({"status": "started"})

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not HA_TOKEN:
        log.error("HA_TOKEN environment variable is required!")
        log.error("Create a long-lived access token in HA: Profile → Security → Long-Lived Access Tokens")
        exit(1)

    # Pre-seed known devices
    _seed_device("192.168.0.14", "SLZB-MR1",  [80, 7638])
    _seed_device("192.168.0.15", "SLZB-MR1U", [80, 6638])

    # Start background pollers
    threading.Thread(target=_ha_poller_loop,          daemon=True, name="ha-poller").start()
    threading.Thread(target=_device_ping_loop,        daemon=True, name="device-ping").start()
    threading.Thread(target=_snmp_poller_loop,        daemon=True, name="snmp-poller").start()
    threading.Thread(target=_meraki_api_poller_loop,  daemon=True, name="meraki-api-poller").start()
    threading.Thread(target=_peer_health_loop,        daemon=True, name="peer-health").start()
    threading.Thread(target=_primary_peer_check_loop, daemon=True, name="peer-check").start()
    threading.Thread(target=_feature_probe_loop,      daemon=True, name="feature-probe").start()

    # Give the first poll a moment
    time.sleep(2)

    port = int(os.environ.get("PORT", "9099"))
    log.info("Starting Farol on port %d", port)
    app.run(host="0.0.0.0", port=port)
