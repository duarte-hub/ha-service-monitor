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
from datetime import datetime, timezone, timedelta

import socket
import subprocess

import websocket
import requests
from flask import Flask, render_template, jsonify, request

# ---------------------------------------------------------------------------
# Configuration (all via environment variables)
# ---------------------------------------------------------------------------
HA_URL = os.environ.get("HA_URL", "http://192.168.0.20:8123")
HA_TOKEN = os.environ.get("HA_TOKEN", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "30"))  # seconds

# Email config
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", SMTP_USER)
EMAIL_TO = os.environ.get("EMAIL_TO", "")
ALERT_COOLDOWN = int(os.environ.get("ALERT_COOLDOWN", "300"))  # seconds
NOTIFY_SERVICE = os.environ.get("NOTIFY_SERVICE", "notify.mobile_app_iphoned")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_LOG_BUFFER: list[str] = []
_LOG_BUFFER_MAX = 2000

class _BufferHandler(logging.Handler):
    def emit(self, record):
        _LOG_BUFFER.append(self.format(record))
        if len(_LOG_BUFFER) > _LOG_BUFFER_MAX:
            del _LOG_BUFFER[0]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ha-monitor")
_buf_handler = _BufferHandler()
_buf_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
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

_DEVICES_PATH = os.environ.get("DEVICES_PATH", "/data/devices.json")
_devices: dict[str, dict] = {}
_devices_lock = threading.Lock()
_scan_status: dict = {"state": "idle", "message": ""}

def _load_devices() -> dict:
    try:
        with open(_DEVICES_PATH) as fh:
            return {d["ip"]: d for d in json.load(fh)}
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
                    "status":         "up",
                    "last_seen":      now,
                    "ping_latency_ms": old.get("ping_latency_ms"),
                }
            _save_devices()
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

def _seed_device(ip: str, name: str, ports: list[int]) -> None:
    with _devices_lock:
        if ip not in _devices:
            _devices[ip] = {
                "ip": ip, "mac": "", "vendor": "", "hostname": "",
                "name": name, "monitored": True, "status": "unknown",
                "last_seen": None, "ping_latency_ms": None,
                "ports": ports, "port_status": {},
            }
            log.info("Seeded device %s (%s) with ports %s", ip, name, ports)
        else:
            _devices[ip]["ports"] = ports
            log.info("Updated seed ports for %s: %s", ip, ports)
        _save_devices()

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
        label = dev.get("name") or dev.get("hostname") or ip
        log.debug("monitored %s (%s): %s", label, ip, "up" if up else "down")
        if prev != "down" and not up:
            maybe_alert(f"device_{ip}", f"{label} unreachable", f"{ip} is not responding to ping")
        elif prev == "down" and up:
            log.info("Device %s (%s) is back online", label, ip)
            if notify_recovery:
                maybe_alert(f"device_{ip}_recovery", f"{label} back online", f"{ip} is responding again")

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
                    maybe_alert(f"port_{ip}_{p_str}", f"{label} port {p_str} closed", f"{ip}:{p_str} is not responding")
                elif prev_up is False and port_up:
                    log.info("Port %s:%s back online", ip, p_str)
                    if notify_recovery:
                        maybe_alert(f"port_{ip}_{p_str}_recovery", f"{label} port {p_str} open", f"{ip}:{p_str} is responding again")

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
        vendor = ""
        try:
            resp = requests.get(
                f"https://api.macvendors.com/{mac[:8]}",
                timeout=5, headers={"Accept": "text/plain"},
            )
            _mac_vendor_last_call = time.time()
            if resp.status_code == 200:
                vendor = resp.text.strip()
        except Exception:
            pass
        _mac_vendor_cache[oui] = vendor
        _save_mac_vendor_cache()
        log.debug("MAC vendor %s → %s", oui, vendor or "(unknown)")
    return vendor

def _snmpwalk(host: str, community: str, oid: str, timeout: int = 10) -> list[tuple[str, str]]:
    """Run snmpwalk -v2c, return [(oid_str, value_str)] or [] on error."""
    try:
        r = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, "-On", host, oid],
            capture_output=True, text=True, timeout=timeout,
        )
        pairs = []
        for line in r.stdout.splitlines():
            if " = " not in line:
                continue
            oid_part, val_part = line.split(" = ", 1)
            pairs.append((oid_part.strip(), val_part.strip()))
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
        name = dev.get("name", host)
        log.info("SNMP querying %s (%s)", name, host)

        # ARP table: OID index is {ifIndex}.{ip0}.{ip1}.{ip2}.{ip3}, value is MAC
        ip_to_mac: dict[str, str] = {}
        for oid_str, val_str in _snmpwalk(host, community, "1.3.6.1.2.1.4.22.1.2"):
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

        # Bridge forwarding table: value is MAC (covers wireless clients on APs too)
        bridge_macs: set[str] = set()
        for _oid, val_str in _snmpwalk(host, community, "1.3.6.1.2.1.17.4.3.1.1"):
            mac = _parse_snmp_mac(val_str)
            if mac:
                bridge_macs.add(mac)

        log.info("SNMP %s: %d ARP entries, %d bridge MACs", name, len(ip_to_mac), len(bridge_macs))

        changed = False
        for ip, mac in ip_to_mac.items():
            if int(mac.split(":")[0], 16) & 0x01:
                continue  # skip multicast
            vendor = _mac_vendor(mac)
            with _devices_lock:
                if ip not in _devices:
                    _devices[ip] = {
                        "ip": ip, "mac": mac, "vendor": vendor,
                        "hostname": "", "name": "",
                        "monitored": False, "status": "unknown",
                        "last_seen": None, "ping_latency_ms": None,
                        "ports": [], "port_status": {},
                    }
                    log.info("SNMP discovered %s — %s (%s)", ip, mac, vendor or "unknown vendor")
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
        if changed:
            _save_devices()
    return new_count

def _snmp_poller_loop() -> None:
    time.sleep(15)  # let the app fully start before first poll
    while True:
        try:
            _poll_snmp_devices()
        except Exception as e:
            log.exception("SNMP poll error: %s", e)
        time.sleep(300)

# ---------------------------------------------------------------------------
# Runtime config overlay (persisted to disk, overrides env vars at runtime)
# ---------------------------------------------------------------------------
_CONFIG_PATH = os.environ.get("CONFIG_PATH", "/data/monitor_config.json")
_CONFIG_FIELDS = {
    "notify_service":    {"label": "Push notify service", "default": NOTIFY_SERVICE},
    "smtp_host":         {"label": "SMTP host",           "default": SMTP_HOST},
    "smtp_port":         {"label": "SMTP port",           "default": str(SMTP_PORT)},
    "smtp_user":         {"label": "SMTP user",           "default": SMTP_USER},
    "smtp_pass":         {"label": "SMTP password",       "default": SMTP_PASS, "secret": True},
    "email_from":        {"label": "Email from",          "default": EMAIL_FROM},
    "email_to":          {"label": "Email to",            "default": EMAIL_TO},
    "alert_cooldown":         {"label": "Alert cooldown (s)",              "default": str(ALERT_COOLDOWN)},
    "push_alerts_enabled":    {"label": "Push alerts enabled",             "default": "true"},
    "email_alerts_enabled":   {"label": "Email alerts enabled",            "default": "false"},
    "alert_title":            {"label": "Notification title prefix",       "default": "HA Monitor"},
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
email_alerts_enabled: bool = False
ALERT_TITLE:          str  = "HA Monitor"
notify_recovery:      bool = False

def _apply_config(data: dict) -> None:
    global NOTIFY_SERVICE, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
    global EMAIL_FROM, EMAIL_TO, ALERT_COOLDOWN, push_alerts_enabled, email_alerts_enabled
    global ALERT_TITLE, notify_recovery
    if "notify_service"       in data: NOTIFY_SERVICE        = data["notify_service"]
    if "smtp_host"            in data: SMTP_HOST             = data["smtp_host"]
    if "smtp_port"            in data: SMTP_PORT             = int(data["smtp_port"] or 587)
    if "smtp_user"            in data: SMTP_USER             = data["smtp_user"]
    if "smtp_pass"            in data: SMTP_PASS             = data["smtp_pass"]
    if "email_from"           in data: EMAIL_FROM            = data["email_from"]
    if "email_to"             in data: EMAIL_TO              = data["email_to"]
    if "alert_cooldown"       in data: ALERT_COOLDOWN        = int(data["alert_cooldown"] or 300)
    if "push_alerts_enabled"  in data: push_alerts_enabled   = str(data["push_alerts_enabled"]).lower() in ("true", "1", "yes")
    if "email_alerts_enabled" in data: email_alerts_enabled  = str(data["email_alerts_enabled"]).lower() in ("true", "1", "yes")
    if "alert_title"          in data: ALERT_TITLE           = data["alert_title"] or "HA Monitor"
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

_runtime_config = _load_config()
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
def send_push(subject: str, body: str):
    """Send a push notification via the HA companion app."""
    try:
        service_parts = NOTIFY_SERVICE.split(".", 1)
        if len(service_parts) != 2:
            log.error("Invalid NOTIFY_SERVICE: %s", NOTIFY_SERVICE)
            return
        domain, service = service_parts

        url = f"{HA_URL}/api/services/{domain}/{service}"
        payload = {
            "title": f"{ALERT_TITLE}: {subject}",
            "message": body,
            "data": {
                "push": {
                    "sound": {"name": "default", "critical": 1, "volume": 0.8},
                },
                "url": "/config/dashboard",
                "group": "ha-monitor",
            },
        }
        resp = requests.post(url, headers=ha_headers(), json=payload, timeout=10)
        resp.raise_for_status()
        log.info("Push notification sent: %s", subject)
    except Exception as e:
        log.error("Failed to send push: %s", e)


def send_email(subject: str, body: str):
    if not SMTP_HOST or not EMAIL_TO:
        log.warning("Email alert skipped — SMTP not configured")
        return
    try:
        msg = MIMEMultipart()
        msg["From"]    = EMAIL_FROM or SMTP_USER
        msg["To"]      = EMAIL_TO
        msg["Subject"] = f"{ALERT_TITLE}: {subject}"
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(msg["From"], [EMAIL_TO], msg.as_string())
        log.info("Email alert sent: %s", subject)
    except Exception as e:
        log.error("Failed to send email alert: %s", e)


def maybe_alert(key: str, subject: str, detail: str):
    """Send alert if cooldown has elapsed and alerts are enabled."""
    if not alerts_enabled:
        return
    now = time.time()
    last = alert_history.get(key, 0)
    if now - last >= ALERT_COOLDOWN:
        alert_history[key] = now
        if push_alerts_enabled:
            threading.Thread(target=send_push, args=(subject, detail), daemon=True).start()
        if email_alerts_enabled:
            threading.Thread(target=send_email, args=(subject, detail), daemon=True).start()


# ---------------------------------------------------------------------------
# Background poller
# ---------------------------------------------------------------------------
def poller_loop():
    while True:
        try:
            poll_once()
        except Exception as e:
            log.exception("Unhandled error in poller: %s", e)
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
    return render_template("index.html", state=state, poll_interval=POLL_INTERVAL)


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
    return jsonify(devs)


@app.route("/api/devices/<ip>", methods=["PATCH"])
def api_device_patch(ip):
    with _devices_lock:
        if ip not in _devices:
            return jsonify({"error": "not found"}), 404
        for k in ("name", "monitored", "ports"):
            if k in (request.json or {}):
                _devices[ip][k] = request.json[k]
        _save_devices()
        return jsonify(_devices[ip])


@app.route("/api/devices/<ip>", methods=["DELETE"])
def api_device_delete(ip):
    with _devices_lock:
        _devices.pop(ip, None)
        _save_devices()
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
    if not host:
        return jsonify({"ok": False, "error": "host required"}), 400
    # Quick test: walk sysDescr (1.3.6.1.2.1.1.1.0) — supported by virtually all SNMP devices
    rows = _snmpwalk(host, community, "1.3.6.1.2.1.1.1.0", timeout=5)
    if rows:
        descr = rows[0][1].replace("STRING:", "").strip().strip('"')
        # Also grab a quick ARP count
        arp = _snmpwalk(host, community, "1.3.6.1.2.1.4.22.1.2", timeout=5)
        bridge = _snmpwalk(host, community, "1.3.6.1.2.1.17.4.3.1.1", timeout=5)
        return jsonify({
            "ok": True,
            "description": descr,
            "arp_entries": len(arp),
            "bridge_macs": len(bridge),
        })
    return jsonify({"ok": False, "error": f"No SNMP response from {host} (check host, community string, and that SNMP is enabled)"})


@app.route("/api/snmp_poll", methods=["POST"])
def api_snmp_poll():
    with _snmp_lock:
        if not _snmp_devices:
            return jsonify({"ok": False, "error": "No SNMP devices configured"}), 400
    threading.Thread(target=_poll_snmp_devices, daemon=True).start()
    return jsonify({"ok": True, "message": "Poll started"})


@app.route("/api/update", methods=["POST"])
def api_update():
    """Rebuild image from /app-src and restart with preserved settings."""

    def _do_update():
        try:
            inspect = subprocess.run(
                ["docker", "inspect", "ha-service-monitor", "--format", "{{json .Config.Env}}"],
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

            log.info("Update: building ha-service-monitor:latest ...")
            build = subprocess.run(
                ["docker", "build", "-t", "ha-service-monitor:latest", "/app-src"],
                capture_output=True, text=True, timeout=300,
            )
            if build.returncode != 0:
                log.error("Update: build failed:\n%s", build.stderr)
                return
            log.info("Update: build complete")

            restart_script = (
                "sleep 2 && "
                "docker stop ha-service-monitor; "
                "docker rm ha-service-monitor; "
                "docker run -d"
                " --name ha-service-monitor"
                " --restart unless-stopped"
                " -p 9099:9099"
                " -v /var/run/docker.sock:/var/run/docker.sock"
                " -v /usr/bin/docker:/usr/bin/docker:ro"
                " -v /mnt/user/appdata/ha-monitor:/app-src"
                " --env-file /app-src/container.env"
                " ha-service-monitor:latest"
            )
            r = subprocess.run(
                [
                    "docker", "run", "-d", "--rm",
                    "--name", "ha-monitor-updater",
                    "-v", "/var/run/docker.sock:/var/run/docker.sock",
                    "-v", "/usr/bin/docker:/usr/bin/docker:ro",
                    "-v", "/mnt/user/appdata/ha-monitor:/app-src",
                    "ha-service-monitor:latest",
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
    safe = {k: ("••••••" if _CONFIG_FIELDS[k].get("secret") and v else v)
            for k, v in _runtime_config.items() if k in _CONFIG_FIELDS}
    return jsonify(safe)


@app.route("/logs")
def logs_page():
    return render_template("logs.html")

@app.route("/api/logs")
def api_logs():
    n = min(int(request.args.get("n", 500)), _LOG_BUFFER_MAX)
    return jsonify({"lines": _LOG_BUFFER[-n:], "verbose": _buf_handler.level == logging.DEBUG})


@app.route("/api/logs/level", methods=["POST"])
def api_logs_level():
    enabled = (request.json or {}).get("verbose", False)
    _set_verbose(enabled)
    log.info("Verbose logging %s", "enabled" if enabled else "disabled")
    return jsonify({"verbose": enabled})


@app.route("/api/test_push", methods=["POST"])
def api_test_push():
    try:
        send_push("Test notification", "HA Monitor push notifications are working.")
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
        msg["Subject"] = "HA Monitor — test email"
        msg.attach(MIMEText("HA Monitor email alerts are working.", "plain"))
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
                    _dbg(f"Install attempt {install_attempt + 1} error: {ie}")
                    # Check whether the addon is actually present now (HA async quirk)
                    try:
                        probe = _ws_sup("GET", f"/addons/{Z2M_EDGE_SLUG}/info")
                        _dbg(f"Post-install probe: state={probe.get('state')}, version={probe.get('version')}")
                        _dbg("Addon present after install error — continuing with config restore")
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
    t = threading.Thread(target=poller_loop, daemon=True)
    t.start()
    threading.Thread(target=_snmp_poller_loop, daemon=True, name="snmp-poller").start()

    # Give the first poll a moment
    time.sleep(2)

    port = int(os.environ.get("PORT", "9099"))
    log.info("Starting HA Service Monitor on port %d", port)
    app.run(host="0.0.0.0", port=port)
