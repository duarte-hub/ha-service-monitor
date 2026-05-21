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
import sqlite3
import logging
import smtplib
import ipaddress
import collections
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

# ---------------------------------------------------------------------------
# SQLite database
# ---------------------------------------------------------------------------
_DB_PATH = os.environ.get("DB_PATH", "/data/farol.db")


def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _db_init() -> None:
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = _db_conn()
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS devices (ip TEXT PRIMARY KEY, data TEXT NOT NULL DEFAULT '{}')")
        conn.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')")
        conn.execute("CREATE TABLE IF NOT EXISTS mac_vendors (oui TEXT PRIMARY KEY, vendor TEXT NOT NULL DEFAULT '')")
        conn.execute("CREATE TABLE IF NOT EXISTS mac_ports (mac TEXT PRIMARY KEY, data TEXT NOT NULL DEFAULT '{}')")
        conn.execute("CREATE TABLE IF NOT EXISTS vuln_results (ip TEXT PRIMARY KEY, data TEXT NOT NULL DEFAULT '{}')")
        conn.commit()
    finally:
        conn.close()


try:
    _db_init()
except Exception as _db_init_err:
    log.error("SQLite init failed (%s) — persistence will degrade to JSON fallback", _db_init_err)

# ---------------------------------------------------------------------------

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
        with _db_conn() as conn:
            row = conn.execute("SELECT value FROM kv WHERE key='alerts_enabled'").fetchone()
        if row:
            return row[0] == "1"
    except Exception:
        pass
    # migrate from JSON
    try:
        with open(_ALERTS_STATE_PATH) as fh:
            val = json.load(fh).get("enabled", True)
        _persist_alerts_enabled(val)
        return val
    except Exception:
        return True

def _persist_alerts_enabled(val: bool) -> None:
    try:
        with _db_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO kv (key, value) VALUES ('alerts_enabled', ?)",
                         ("1" if val else "0",))
    except Exception as e:
        log.warning("Failed to persist alerts_enabled: %s", e)

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

_DOCKER_NETS = [ipaddress.IPv4Network("172.16.0.0/12"), ipaddress.IPv4Network("127.0.0.0/8")]

def _is_docker_ip(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in _DOCKER_NETS)
    except Exception:
        return False

def _load_devices() -> dict:
    try:
        with _db_conn() as conn:
            rows = conn.execute("SELECT ip, data FROM devices").fetchall()
        if rows:
            devs = {}
            for row in rows:
                try:
                    d = json.loads(row["data"])
                    if not _is_docker_ip(d["ip"]):
                        d["port_status"] = {}
                        devs[d["ip"]] = d
                except Exception:
                    pass
            return devs
    except Exception as e:
        log.warning("DB load devices failed: %s", e)
    # migrate from JSON
    try:
        with open(_DEVICES_PATH) as fh:
            devs = {d["ip"]: d for d in json.load(fh) if not _is_docker_ip(d["ip"])}
        for d in devs.values():
            d["port_status"] = {}
        if devs:
            log.info("Migrating %d devices from JSON to SQLite", len(devs))
            _save_devices_bulk(devs)
        return devs
    except Exception:
        return {}

def _save_devices_bulk(devs: dict) -> None:
    try:
        rows = [(ip, json.dumps(d)) for ip, d in devs.items()]
        with _db_conn() as conn:
            conn.executemany("INSERT OR REPLACE INTO devices (ip, data) VALUES (?, ?)", rows)
    except Exception as e:
        log.warning("DB save devices bulk failed: %s", e)

def _save_devices() -> None:
    try:
        with _devices_lock:
            devs = dict(_devices)
        _save_devices_bulk(devs)
    except Exception as e:
        log.error("Failed to save devices: %s", e)

def _db_upsert_device(d: dict) -> None:
    try:
        with _db_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO devices (ip, data) VALUES (?, ?)",
                         (d["ip"], json.dumps(d)))
    except Exception as e:
        log.error("DB upsert device %s: %s", d.get("ip"), e)

_devices = _load_devices()
_seen_device_ips: set = set(_devices.keys())

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


# ── Per-device full nmap scan ─────────────────────────────────────────────────
_nmap_scan_results: dict = {}
_nmap_scanning:     set  = set()

def _parse_nmap_full(xml_str: str) -> dict:
    out: dict = {"ts": datetime.now().isoformat(), "status": "done",
                 "ports": [], "os": [], "hostnames": [], "host_scripts": []}
    try:
        root = ET.fromstring(xml_str)
    except Exception as e:
        out.update({"status": "error", "error": f"XML parse error: {e}"}); return out
    host = root.find("host")
    if host is None:
        out["status"] = "no_host"; return out
    for hn in host.findall("hostnames/hostname"):
        name = hn.get("name", "")
        if name: out["hostnames"].append(name)
    for port_el in host.findall("ports/port"):
        st = port_el.find("state")
        if st is None or st.get("state") != "open":
            continue
        svc = port_el.find("service")
        p: dict = {
            "port":      int(port_el.get("portid", 0)),
            "proto":     port_el.get("protocol", "tcp"),
            "name":      svc.get("name", "")      if svc is not None else "",
            "product":   svc.get("product", "")   if svc is not None else "",
            "version":   svc.get("version", "")   if svc is not None else "",
            "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
            "tunnel":    svc.get("tunnel", "")    if svc is not None else "",
            "scripts":   [],
        }
        for sc in port_el.findall("script"):
            sid, sout = sc.get("id", ""), sc.get("output", "").strip()
            if sid and sout: p["scripts"].append({"id": sid, "output": sout})
        out["ports"].append(p)
    for om in host.findall("os/osmatch"):
        out["os"].append({"name": om.get("name", ""), "accuracy": int(om.get("accuracy", 0))})
    out["os"].sort(key=lambda x: -x["accuracy"])
    for sc in host.findall("hostscript/script"):
        sid, sout = sc.get("id", ""), sc.get("output", "").strip()
        if sid and sout: out["host_scripts"].append({"id": sid, "output": sout})
    return out

def _run_nmap_full(ip: str) -> None:
    _nmap_scanning.add(ip)
    try:
        cmd = ["nmap", "-sV", "-sC", "-T4", "--open", "-oX", "-", ip]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        _nmap_scan_results[ip] = _parse_nmap_full(r.stdout)
        log.info("Nmap scan %s: %d open ports", ip, len(_nmap_scan_results[ip].get("ports", [])))
    except FileNotFoundError:
        _nmap_scan_results[ip] = {"ts": datetime.now().isoformat(), "status": "error",
                                   "error": "nmap is not installed on this system"}
    except subprocess.TimeoutExpired:
        _nmap_scan_results[ip] = {"ts": datetime.now().isoformat(), "status": "error",
                                   "error": "Scan timed out (>3 min)"}
    except Exception as e:
        _nmap_scan_results[ip] = {"ts": datetime.now().isoformat(), "status": "error", "error": str(e)}
    finally:
        _nmap_scanning.discard(ip)


_nmap_all_status: dict = {"state": "idle", "done": 0, "total": 0, "errors": 0}
_nmap_all_lock = threading.Lock()
_NMAP_ALL_CONCURRENCY = 4


def _run_nmap_all(ips: list) -> None:
    global _nmap_all_status
    sem = threading.Semaphore(_NMAP_ALL_CONCURRENCY)

    def _one(ip: str) -> None:
        with sem:
            _run_nmap_full(ip)
            with _nmap_all_lock:
                _nmap_all_status["done"] += 1
                if _nmap_scan_results.get(ip, {}).get("status") == "error":
                    _nmap_all_status["errors"] += 1

    threads = [threading.Thread(target=_one, args=(ip,), daemon=True) for ip in ips]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with _nmap_all_lock:
        _nmap_all_status["state"] = "done"
    log.info("Nmap all-hosts scan complete: %d/%d, %d errors",
             _nmap_all_status["done"], _nmap_all_status["total"], _nmap_all_status["errors"])


# ── Vulnerability scanning ───────────────────────────────────────────────────
_vuln_results:  dict = {}   # ip → {ts, status, findings: [...]}
_vuln_scanning: set  = set()
_vuln_lock = threading.Lock()
_VULN_RESULTS_PATH = os.environ.get("VULN_RESULTS_PATH", "/data/vuln_results.json")

def _save_vuln_results() -> None:
    try:
        rows = [(ip, json.dumps(data)) for ip, data in _vuln_results.items()]
        with _db_conn() as conn:
            conn.execute("DELETE FROM vuln_results")
            if rows:
                conn.executemany("INSERT INTO vuln_results (ip, data) VALUES (?, ?)", rows)
    except Exception as e:
        log.warning("Failed to save vuln results: %s", e)

def _load_vuln_results() -> dict:
    try:
        with _db_conn() as conn:
            rows = conn.execute("SELECT ip, data FROM vuln_results").fetchall()
        if rows:
            return {r["ip"]: json.loads(r["data"]) for r in rows}
    except Exception as e:
        log.warning("DB load vuln_results failed: %s", e)
    # migrate from JSON
    try:
        with open(_VULN_RESULTS_PATH) as fh:
            return json.load(fh)
    except Exception:
        return {}

# Rolling log buffer — last 1000 lines, seq-numbered for incremental polling
_vuln_log: collections.deque = collections.deque(maxlen=1000)
_vuln_log_seq: int = 0
_vuln_log_lock = threading.Lock()


def _vlog(level: str, msg: str, *args) -> None:
    global _vuln_log_seq
    text = msg % args if args else msg
    getattr(log, level, log.info)(text)
    with _vuln_log_lock:
        _vuln_log_seq += 1
        _vuln_log.append({"seq": _vuln_log_seq, "ts": time.time(),
                          "level": level, "msg": text})


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# Runtime-configurable vuln settings (overridden by _apply_config)
VULN_AUTO_SCAN_ENABLED:       bool = True
VULN_AUTO_SCAN_INTERVAL:      int  = 24     # hours between auto sweeps
VULN_SCAN_DELAY:              int  = 15     # seconds between host starts in auto-sweep
VULN_CONCURRENCY:             int  = 2      # max parallel scans
VULN_EXCLUDE_IPS:             set  = set()  # IPs to skip entirely
VULN_SCAN_ON_NEW_DEVICE:      bool = False

VULN_NMAP_ENABLED:            bool = True
VULN_NMAP_TIMING:             str  = "T4"
VULN_NMAP_SCRIPTS:            str  = "vuln"
VULN_NMAP_PORTS:              str  = ""     # empty → nmap default

VULN_NUCLEI_ENABLED:          bool = True
VULN_NUCLEI_TAGS:             str  = ""
VULN_NUCLEI_EXCLUDE_TAGS:     str  = ""
VULN_NUCLEI_SEVERITY:         str  = "critical,high,medium,low,info"
VULN_NUCLEI_RATE_LIMIT:       int  = 50
VULN_NUCLEI_TIMEOUT:          int  = 10
VULN_NUCLEI_CONCURRENCY:      int  = 25
VULN_NUCLEI_BULK_SIZE:        int  = 25
VULN_NUCLEI_RETRIES:          int  = 1
VULN_NUCLEI_MAX_HOST_ERRORS:  int  = 30
VULN_NUCLEI_INTERACTSH:       bool = False
VULN_NUCLEI_HEADLESS:         bool = False
VULN_NUCLEI_CUSTOM_TEMPLATES: str  = ""


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"


def _parse_nmap_vuln(xml_str: str) -> list:
    findings = []
    try:
        root = ET.fromstring(xml_str)
    except Exception:
        return findings

    for host in root.findall("host"):
        scripts: list = []
        hs = host.find("hostscript")
        if hs is not None:
            scripts.extend(hs.findall("script"))
        for port_el in host.findall(".//port"):
            scripts.extend(port_el.findall("script"))

        for sc in scripts:
            sid  = sc.get("id", "")
            sout = sc.get("output", "")
            if "VULNERABLE" not in sout.upper():
                continue
            cves_found = re.findall(r"CVE-\d{4}-\d+", sout, re.IGNORECASE)
            cvss_m     = re.search(r"CVSS:\s*([\d.]+)", sout, re.IGNORECASE)
            if cvss_m:
                try:    severity = _cvss_to_severity(float(cvss_m.group(1)))
                except: severity = "high"
            elif "CRITICAL" in sout.upper(): severity = "critical"
            elif "MEDIUM"   in sout.upper(): severity = "medium"
            elif "LOW"      in sout.upper(): severity = "low"
            else:                            severity = "high"

            findings.append({
                "source":      "nmap",
                "severity":    severity,
                "name":        sid,
                "description": sout[:600].strip(),
                "cve":         cves_found[0] if cves_found else "",
                "matched_at":  "",
            })
    return findings


def _parse_nuclei_output(output: str) -> list:
    findings = []
    for raw in output.splitlines():
        raw = raw.strip()
        if not raw or not raw.startswith("{"):
            continue
        try:
            item = json.loads(raw)
        except Exception:
            continue
        info = item.get("info", {})
        sev  = (info.get("severity") or "info").lower()
        if sev not in _SEVERITY_ORDER:
            sev = "info"
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        cve = next((r.split("/")[-1].upper() for r in refs if "CVE-" in r.upper()), "")
        findings.append({
            "source":      "nuclei",
            "severity":    sev,
            "name":        info.get("name") or item.get("template-id", ""),
            "description": (info.get("description") or "")[:600],
            "cve":         cve,
            "matched_at":  item.get("matched-at", ""),
        })
    return findings


_vuln_sem = threading.Semaphore(VULN_CONCURRENCY)


def _run_vuln_scan(ip: str) -> None:
    with _vuln_sem:
        if ip in VULN_EXCLUDE_IPS:
            _vlog("info", "[%s] skipped (in exclusion list)", ip)
            return
        with _vuln_lock:
            _vuln_scanning.add(ip)
        _vuln_results[ip] = {"ts": None, "status": "running", "findings": []}
        try:
            findings: list = []

            # Phase 1: nmap --script <scripts>
            if VULN_NMAP_ENABLED:
                try:
                    cmd = ["nmap", "-sV",
                           "--script", VULN_NMAP_SCRIPTS,
                           f"-{VULN_NMAP_TIMING}",
                           "-oX", "-"]
                    if VULN_NMAP_PORTS:
                        cmd += ["-p", VULN_NMAP_PORTS]
                    cmd.append(ip)
                    _vlog("info", "[%s] nmap phase starting: %s", ip, " ".join(cmd))
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    nmap_findings = _parse_nmap_vuln(r.stdout) if r.stdout else []
                    findings.extend(nmap_findings)
                    _vlog("info", "[%s] nmap phase done: %d finding(s)", ip, len(nmap_findings))
                    if r.stderr and r.stderr.strip():
                        for line in r.stderr.strip().splitlines():
                            _vlog("info", "[%s] nmap stderr: %s", ip, line)
                except FileNotFoundError:
                    _vlog("warning", "[%s] nmap not installed; skipping nmap phase", ip)
                except subprocess.TimeoutExpired:
                    _vlog("warning", "[%s] nmap phase timed out (>300 s)", ip)
                except Exception as e:
                    _vlog("error", "[%s] nmap phase error: %s", ip, e)
            else:
                _vlog("info", "[%s] nmap phase disabled", ip)

            # Phase 2: Nuclei
            if VULN_NUCLEI_ENABLED:
                try:
                    cmd = [
                        "nuclei", "-u", ip,
                        "-severity",    VULN_NUCLEI_SEVERITY,
                        "-rate-limit",  str(VULN_NUCLEI_RATE_LIMIT),
                        "-timeout",     str(VULN_NUCLEI_TIMEOUT),
                        "-c",           str(VULN_NUCLEI_CONCURRENCY),
                        "-bulk-size",   str(VULN_NUCLEI_BULK_SIZE),
                        "-retries",     str(VULN_NUCLEI_RETRIES),
                        "-max-host-error", str(VULN_NUCLEI_MAX_HOST_ERRORS),
                        "-jsonl", "-no-color",
                    ]
                    # VULN_NUCLEI_TAGS is used as a tag filter (-tags), not a directory
                    # filter (-t). Leaving it empty runs all templates (filtered by severity).
                    if VULN_NUCLEI_TAGS:
                        cmd += ["-tags", VULN_NUCLEI_TAGS]
                    if VULN_NUCLEI_EXCLUDE_TAGS:
                        cmd += ["-etags", VULN_NUCLEI_EXCLUDE_TAGS]
                    if VULN_NUCLEI_INTERACTSH:
                        cmd.append("-ni")
                    if VULN_NUCLEI_HEADLESS:
                        cmd.append("-headless")
                    if VULN_NUCLEI_CUSTOM_TEMPLATES:
                        cmd += ["-t", VULN_NUCLEI_CUSTOM_TEMPLATES]
                    _vlog("info", "[%s] nuclei phase starting (tags: %s, severity: %s) cmd: %s",
                          ip, VULN_NUCLEI_TAGS, VULN_NUCLEI_SEVERITY, " ".join(cmd))
                    r = subprocess.run(cmd, capture_output=True, text=True,
                                       timeout=1800)
                    nuclei_findings = _parse_nuclei_output(r.stdout) if r.stdout else []
                    findings.extend(nuclei_findings)
                    _vlog("info", "[%s] nuclei phase done: %d finding(s) (exit=%d stdout=%d stderr=%d)",
                          ip, len(nuclei_findings), r.returncode, len(r.stdout or ""), len(r.stderr or ""))
                    if r.stdout and not nuclei_findings:
                        _vlog("info", "[%s] nuclei raw stdout (first 500): %s", ip, r.stdout[:500])
                    for line in (r.stderr or "").strip().splitlines():
                        if line.strip():
                            _vlog("info", "[%s] nuclei: %s", ip, line)
                except FileNotFoundError:
                    _vlog("warning", "[%s] nuclei not installed; skipping nuclei phase", ip)
                except subprocess.TimeoutExpired:
                    _vlog("warning", "[%s] nuclei phase timed out", ip)
                except Exception as e:
                    _vlog("error", "[%s] nuclei phase error: %s", ip, e)
            else:
                _vlog("info", "[%s] nuclei phase disabled", ip)

            # Deduplicate by (name, source) and sort by severity
            seen: set = set()
            deduped   = []
            for f in findings:
                key = (f["name"].lower(), f["source"])
                if key not in seen:
                    seen.add(key)
                    deduped.append(f)
            deduped.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))

            _vuln_results[ip] = {
                "ts":       time.time(),
                "status":   "done",
                "findings": deduped,
            }
            _save_vuln_results()
            _vlog("info", "[%s] scan complete: %d unique finding(s) (critical=%d high=%d medium=%d low=%d)",
                  ip,
                  len(deduped),
                  sum(1 for f in deduped if f["severity"] == "critical"),
                  sum(1 for f in deduped if f["severity"] == "high"),
                  sum(1 for f in deduped if f["severity"] == "medium"),
                  sum(1 for f in deduped if f["severity"] == "low"))
        except Exception as e:
            _vlog("error", "[%s] scan failed: %s", ip, e)
            _vuln_results[ip] = {"ts": time.time(), "status": "error", "findings": []}
            _save_vuln_results()
        finally:
            with _vuln_lock:
                _vuln_scanning.discard(ip)


def _nuclei_update_templates() -> None:
    """Update nuclei templates at startup so scans use the latest template set."""
    try:
        ver = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=10)
        log.info("nuclei binary: %s", (ver.stderr or ver.stdout or "unknown").strip().splitlines()[0])
    except FileNotFoundError:
        log.warning("nuclei not found — vuln nuclei phase will be skipped")
        return
    except Exception as e:
        log.warning("nuclei version check failed: %s", e)
    try:
        r = subprocess.run(["nuclei", "-update-templates"], capture_output=True, text=True, timeout=120)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        if r.returncode == 0:
            log.info("nuclei templates updated: %s", out[:200] if out else "ok")
        else:
            log.warning("nuclei template update exited %d: %s", r.returncode, out[:200])
    except Exception as e:
        log.warning("nuclei template update failed: %s", e)


def _vuln_auto_scan_loop() -> None:
    """Runs a full network vuln sweep on the configured interval."""
    time.sleep(300)   # wait 5 min after startup before first auto-sweep
    while True:
        if not VULN_AUTO_SCAN_ENABLED:
            time.sleep(60)
            continue
        with _devices_lock:
            ips = [ip for ip in _devices if ip not in VULN_EXCLUDE_IPS]
        _vlog("info", "[auto-sweep] starting sweep of %d hosts (interval=%dh delay=%ds)",
              len(ips), VULN_AUTO_SCAN_INTERVAL, VULN_SCAN_DELAY)
        for ip in ips:
            with _vuln_lock:
                already = ip in _vuln_scanning
            if not already:
                threading.Thread(target=_run_vuln_scan, args=(ip,), daemon=True,
                                 name=f"vuln-{ip}").start()
                time.sleep(VULN_SCAN_DELAY)
        time.sleep(VULN_AUTO_SCAN_INTERVAL * 3600)


# ── SNMP interface diagnostics (IF-MIB) ──────────────────────────────────────
_SNMP_IF_RESULTS: dict = {}   # ip → result
_SNMP_IF_RUNNING: set  = set()

# IF-MIB column numbers → field names
_IF_COL: dict = {
    "2": "descr", "5": "speed", "6": "phys_addr", "7": "admin", "8": "oper",
    "10": "in_oct", "13": "in_disc", "14": "in_err",
    "16": "out_oct", "19": "out_disc", "20": "out_err",
}
_IFX_COL: dict = {
    "1": "name", "6": "hc_in", "10": "hc_out", "15": "high_speed", "18": "alias",
}
_IF_OPER: dict = {
    "1": "up", "2": "down", "3": "testing", "4": "unknown",
    "5": "dormant", "6": "notPresent", "7": "lowerLayerDown",
}

def _sv(val_str: str) -> str:
    """Strip 'TYPE: ' prefix from snmpwalk value and surrounding quotes."""
    v = val_str.split(": ", 1)[-1].strip() if ": " in val_str else val_str.strip()
    return v.strip('"')

def _si(val_str: str) -> int:
    try: return int(_sv(val_str))
    except (ValueError, TypeError): return 0

def _run_snmp_if_diag(ip: str, community: str) -> None:
    sw_cfg = next((s for s in SNMP_SWITCHES if s.get("ip") == ip), None)
    snmp_port = int(sw_cfg["port"]) if sw_cfg and sw_cfg.get("port") else 161
    _SNMP_IF_RUNNING.add(ip)
    try:
        ifaces: dict = {}  # idx → {field: value}

        def _collect(base_oid: str, col_map: dict) -> None:
            for oid_str, val_str in _snmpwalk(ip, community, base_oid, timeout=25, port=snmp_port):
                parts = oid_str.lstrip(".").split(".")
                if len(parts) < 2:
                    continue
                col_s, idx_s = parts[-2], parts[-1]
                try:
                    idx = int(idx_s)
                except ValueError:
                    continue
                field = col_map.get(col_s)
                if field:
                    if idx not in ifaces:
                        ifaces[idx] = {"idx": idx}
                    ifaces[idx][field] = _sv(val_str)

        _collect("1.3.6.1.2.1.2.2.1",   _IF_COL)
        _collect("1.3.6.1.2.1.31.1.1.1", _IFX_COL)

        iface_list = []
        for idx in sorted(ifaces):
            d = ifaces[idx]
            speed = None
            if "high_speed" in d:
                try: speed = int(d["high_speed"])
                except ValueError: pass
            if speed is None and "speed" in d:
                try: speed = int(d["speed"]) // 1_000_000
                except ValueError: pass
            in_oct  = _si(d["hc_in"])  if "hc_in"  in d else (_si(d["in_oct"])  if "in_oct"  in d else None)
            out_oct = _si(d["hc_out"]) if "hc_out" in d else (_si(d["out_oct"]) if "out_oct" in d else None)
            iface_list.append({
                "idx":       idx,
                "name":      d.get("name") or d.get("descr") or f"if{idx}",
                "alias":     d.get("alias", ""),
                "mac":       _parse_snmp_mac(d["phys_addr"]) if d.get("phys_addr") else "",
                "oper":      _IF_OPER.get(d.get("oper", ""), d.get("oper", "?")),
                "admin":     _IF_OPER.get(d.get("admin", ""), d.get("admin", "?")),
                "speed_mbps": speed,
                "in_err":    _si(d["in_err"])   if "in_err"   in d else None,
                "out_err":   _si(d["out_err"])  if "out_err"  in d else None,
                "in_disc":   _si(d["in_disc"])  if "in_disc"  in d else None,
                "out_disc":  _si(d["out_disc"]) if "out_disc" in d else None,
                "in_octets":  in_oct,
                "out_octets": out_oct,
            })

        _SNMP_IF_RESULTS[ip] = {
            "ts": datetime.now().isoformat(), "status": "done",
            "interfaces": iface_list,
        }
        err_count = sum(1 for i in iface_list if (i["in_err"] or 0) + (i["out_err"] or 0) > 0)
        log.info("SNMP if-diag %s: %d interfaces, %d with errors", ip, len(iface_list), err_count)
        # Auto-run bridge scan so device→port links are up to date
        _run_bridge_scan(ip, community, iface_list)
    except Exception as e:
        _SNMP_IF_RESULTS[ip] = {"ts": datetime.now().isoformat(), "status": "error", "error": str(e)}
    finally:
        _SNMP_IF_RUNNING.discard(ip)


# ── Bridge MIB: MAC → switch port mapping ─────────────────────────────────────
_MAC_PORT_PATH = os.environ.get("MAC_PORT_PATH", "/data/mac_to_port.json")
_mac_to_port: dict = {}   # "aa:bb:cc:dd:ee:ff" → {switch_ip, switch_name, if_name, if_alias, if_idx, port_mac_count, in_err, out_err, in_disc, out_disc}
_mac_port_lock = threading.Lock()
_infra_macs:  set  = set()   # interface MACs of switches/APs themselves — excluded from client lists

def _load_mac_to_port() -> None:
    global _mac_to_port
    try:
        with _db_conn() as conn:
            rows = conn.execute("SELECT mac, data FROM mac_ports").fetchall()
        if rows:
            data = {r["mac"]: json.loads(r["data"]) for r in rows}
            with _mac_port_lock:
                _mac_to_port = data
            log.info("Loaded %d MAC→port entries from DB", len(data))
            return
    except Exception as e:
        log.warning("DB load mac_ports failed: %s", e)
    # migrate from JSON
    try:
        with open(_MAC_PORT_PATH) as fh:
            data = json.load(fh)
        with _mac_port_lock:
            _mac_to_port = data
        log.info("Migrating %d MAC→port entries from JSON to SQLite", len(data))
        _save_mac_to_port()
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning("Failed to load mac_to_port: %s", e)

def _save_mac_to_port() -> None:
    try:
        with _mac_port_lock:
            snap = dict(_mac_to_port)
        rows = [(mac, json.dumps(info)) for mac, info in snap.items()]
        with _db_conn() as conn:
            conn.execute("DELETE FROM mac_ports")
            if rows:
                conn.executemany("INSERT INTO mac_ports (mac, data) VALUES (?, ?)", rows)
    except Exception as e:
        log.warning("Failed to save mac_to_port: %s", e)

def _run_bridge_scan(switch_ip: str, community: str, iface_list: list) -> None:
    """Walk dot1dTpFdbTable to map learned MACs to switch interfaces."""
    global _infra_macs
    sw_cfg = next((s for s in SNMP_SWITCHES if s.get("ip") == switch_ip), None)
    snmp_port = int(sw_cfg["port"]) if sw_cfg and sw_cfg.get("port") else 161
    sw_name   = sw_cfg["name"] if sw_cfg and sw_cfg.get("name") else switch_ip
    # If the source is explicitly typed as "ap", every MAC it learns is a direct
    # wireless association regardless of the bridge interface name (br0, eth0, etc.)
    is_ap_source = sw_cfg.get("type", "switch").lower() == "ap" if sw_cfg else False

    # Register every interface MAC of this device as an infrastructure MAC so
    # downstream switch cards don't show the AP's own BSSIDs as fake clients.
    for iface in iface_list:
        mac = (iface.get("mac") or "").lower().strip()
        if mac and mac != "00:00:00:00:00:00":
            _infra_macs.add(mac)

    # Bridge port → ifIndex
    bport_to_ifidx: dict = {}
    for oid_str, val_str in _snmpwalk(switch_ip, community, "1.3.6.1.2.1.17.1.4.1.2", timeout=15, port=snmp_port):
        parts = oid_str.lstrip(".").split(".")
        try:
            bport_to_ifidx[int(parts[-1])] = int(_sv(val_str))
        except ValueError:
            pass

    # ifIndex → interface record
    ifidx_map = {i["idx"]: i for i in iface_list}

    new_entries: dict = {}

    if bport_to_ifidx:
        # Normal path: we have bridge-port → ifIndex mapping; resolve to interface names
        port_mac_count: dict = {}  # ifidx → count of MACs seen on that port
        base_fdb = "1.3.6.1.2.1.17.4.3.1.2"
        base_len = len(base_fdb.split("."))
        for oid_str, val_str in _snmpwalk(switch_ip, community, base_fdb, timeout=20, port=snmp_port):
            parts = oid_str.lstrip(".").split(".")
            suffix = parts[base_len:]
            if len(suffix) != 6:
                continue
            try:
                mac   = ":".join(f"{int(b):02x}" for b in suffix)
                bport = int(_sv(val_str))
            except ValueError:
                continue
            ifidx = bport_to_ifidx.get(bport)
            if ifidx is None:
                continue
            iface = ifidx_map.get(ifidx)
            if iface is None:
                continue
            port_mac_count[ifidx] = port_mac_count.get(ifidx, 0) + 1
            new_entries[mac] = {
                "switch_ip":    switch_ip,
                "switch_name":  sw_name,
                "if_name":      iface.get("name", f"if{ifidx}"),
                "if_alias":     iface.get("alias", ""),
                "if_idx":       ifidx,
                "is_wireless":  is_ap_source,
                "in_err":       iface.get("in_err"),
                "out_err":      iface.get("out_err"),
                "in_disc":      iface.get("in_disc"),
                "out_disc":     iface.get("out_disc"),
            }
        for entry in new_entries.values():
            entry["port_mac_count"] = port_mac_count.get(entry["if_idx"], 1)

    elif is_ap_source:
        # AP path 1: try Bridge FDB walk — group by bridge-port number.
        # On an AP the uplink port has the fewest MACs; all others are wireless clients.
        bport_macs: dict = {}
        base_fdb = "1.3.6.1.2.1.17.4.3.1.2"
        base_len = len(base_fdb.split("."))
        for oid_str, val_str in _snmpwalk(switch_ip, community, base_fdb, timeout=20, port=snmp_port):
            parts = oid_str.lstrip(".").split(".")
            suffix = parts[base_len:]
            if len(suffix) != 6:
                continue
            try:
                mac   = ":".join(f"{int(b):02x}" for b in suffix)
                bport = int(_sv(val_str))
            except ValueError:
                continue
            bport_macs.setdefault(bport, []).append(mac)

        if bport_macs:
            min_count = min(len(ms) for ms in bport_macs.values())
            uplink_ports = {bp for bp, ms in bport_macs.items() if len(ms) == min_count}
            if len(uplink_ports) == len(bport_macs):
                uplink_ports = set()
            for bport, macs in bport_macs.items():
                if bport in uplink_ports:
                    continue
                for mac in macs:
                    new_entries[mac] = {
                        "switch_ip":    switch_ip,
                        "switch_name":  sw_name,
                        "if_name":      f"radio{bport}",
                        "if_alias":     "",
                        "if_idx":       bport,
                        "is_wireless":  True,
                        "port_mac_count": len(macs),
                        "in_err": None, "out_err": None,
                        "in_disc": None, "out_disc": None,
                    }
            log.info("Bridge scan %s (%s): AP FDB mode, %d client ports, %d MACs",
                     switch_ip, sw_name, len(bport_macs) - len(uplink_ports), len(new_entries))
        else:
            # AP path 2: FDB empty. Try Aruba Instant aiClientTable (enterprise MIB).
            # OID: 1.3.6.1.4.1.14823.2.3.3.1.2.4.1.1.{mac6} → client MAC
            # OID: 1.3.6.1.4.1.14823.2.3.3.1.2.4.1.2.{mac6} → BSSID (radio MAC = identifies SSID)
            # OID: 1.3.6.1.4.1.14823.2.3.3.1.2.4.1.3.{mac6} → client IP
            # OID: 1.3.6.1.4.1.14823.2.3.3.1.2.4.1.5.{mac6} → client hostname
            AI_MAC_COL  = "1.3.6.1.4.1.14823.2.3.3.1.2.4.1.1"
            AI_BSSID_COL = "1.3.6.1.4.1.14823.2.3.3.1.2.4.1.2"
            AI_IP_COL   = "1.3.6.1.4.1.14823.2.3.3.1.2.4.1.3"
            AI_HOST_COL = "1.3.6.1.4.1.14823.2.3.3.1.2.4.1.5"
            ai_base_len = len(AI_MAC_COL.split("."))

            # Build BSSID → SSID map from Aruba aiEssTable.
            # 1.3.6.1.4.1.14823.2.3.3.1.2.3.1.3.{ap_mac6}.{idx} → SSID name (STRING)
            # 1.3.6.1.4.1.14823.2.3.3.1.2.3.1.4.{ap_mac6}.{idx} → BSSID (Hex-STRING)
            # Index is 7 octets: 6 AP MAC + 1 SSID slot index.
            AI_ESS_NAME  = "1.3.6.1.4.1.14823.2.3.3.1.2.3.1.3"
            AI_ESS_BSSID = "1.3.6.1.4.1.14823.2.3.3.1.2.3.1.4"
            ess_base_len = len(AI_ESS_NAME.split("."))
            idx_to_ssid: dict = {}
            for oid_str, val_str in _snmpwalk(switch_ip, community, AI_ESS_NAME, timeout=20, port=snmp_port):
                parts = oid_str.lstrip(".").split(".")
                suffix = tuple(parts[ess_base_len:])
                if len(suffix) == 7:
                    idx_to_ssid[suffix] = _sv(val_str).strip()
            bssid_to_ssid: dict[str, str] = {}
            ess_bssid_base_len = len(AI_ESS_BSSID.split("."))
            for oid_str, val_str in _snmpwalk(switch_ip, community, AI_ESS_BSSID, timeout=20, port=snmp_port):
                parts = oid_str.lstrip(".").split(".")
                suffix = tuple(parts[ess_bssid_base_len:])
                if len(suffix) == 7:
                    bssid = _parse_snmp_mac(val_str)
                    ssid  = idx_to_ssid.get(suffix, "")
                    if bssid and ssid:
                        bssid_to_ssid[bssid] = ssid
            log.debug("Bridge scan %s: aiEssTable → %d BSSID→SSID mappings", switch_ip, len(bssid_to_ssid))

            def _mac_from_ai_suffix(parts: list) -> str:
                suffix = parts[ai_base_len:]
                if len(suffix) != 6:
                    return ""
                try:
                    first = int(suffix[0])
                    if first & 0x01:  # multicast
                        return ""
                    return ":".join(f"{int(b):02x}" for b in suffix)
                except ValueError:
                    return ""

            # Collect client MACs from column 1
            for oid_str, _val in _snmpwalk(switch_ip, community, AI_MAC_COL, timeout=20, port=snmp_port):
                mac = _mac_from_ai_suffix(oid_str.lstrip(".").split("."))
                if not mac:
                    continue
                new_entries[mac] = {
                    "switch_ip":      switch_ip,
                    "switch_name":    sw_name,
                    "if_name":        "wifi",
                    "if_alias":       "",
                    "if_idx":         0,
                    "is_wireless":    True,
                    "port_mac_count": 1,
                    "in_err": None, "out_err": None,
                    "in_disc": None, "out_disc": None,
                }

            # Map BSSID (column 2) → SSID name via iface_list; store in if_name
            for oid_str, val_str in _snmpwalk(switch_ip, community, AI_BSSID_COL, timeout=20, port=snmp_port):
                mac = _mac_from_ai_suffix(oid_str.lstrip(".").split("."))
                if not mac or mac not in new_entries:
                    continue
                bssid = _parse_snmp_mac(val_str)
                ssid  = bssid_to_ssid.get(bssid, "")
                new_entries[mac]["if_name"] = ssid if ssid else "wifi"

            # Enrich with IPs from column 3
            for oid_str, val_str in _snmpwalk(switch_ip, community, AI_IP_COL, timeout=20, port=snmp_port):
                mac = _mac_from_ai_suffix(oid_str.lstrip(".").split("."))
                if mac and mac in new_entries:
                    new_entries[mac]["if_alias"] = _sv(val_str)

            # Enrich with hostnames from column 5
            for oid_str, val_str in _snmpwalk(switch_ip, community, AI_HOST_COL, timeout=20, port=snmp_port):
                mac = _mac_from_ai_suffix(oid_str.lstrip(".").split("."))
                hostname = _sv(val_str).strip()
                if mac and hostname and mac in new_entries:
                    new_entries[mac]["if_alias"] = (
                        f"{hostname} ({new_entries[mac]['if_alias']})"
                        if new_entries[mac]["if_alias"] else hostname
                    )

            if new_entries:
                log.info("Bridge scan %s (%s): Aruba aiClientTable, %d wireless clients",
                         switch_ip, sw_name, len(new_entries))
            else:
                # AP path 3: ARP table fallback (non-Aruba APs)
                # OID: 1.3.6.1.2.1.4.22.1.2.{ifIdx}.{a}.{b}.{c}.{d} → MAC
                arp_base = "1.3.6.1.2.1.4.22.1.2"
                arp_base_len = len(arp_base.split("."))
                infra_ips = {s["ip"] for s in SNMP_SWITCHES}
                infra_ips.add(switch_ip)
                for oid_str, val_str in _snmpwalk(switch_ip, community, arp_base, timeout=20, port=snmp_port):
                    parts = oid_str.lstrip(".").split(".")
                    suffix = parts[arp_base_len:]
                    if len(suffix) != 5:
                        continue
                    try:
                        client_ip = ".".join(suffix[1:5])
                        mac = _parse_snmp_mac(val_str)
                    except Exception:
                        continue
                    if not mac or client_ip in infra_ips:
                        continue
                    if int(mac.split(":")[0], 16) & 0x01:
                        continue
                    new_entries[mac] = {
                        "switch_ip":      switch_ip,
                        "switch_name":    sw_name,
                        "if_name":        "wifi",
                        "if_alias":       client_ip,
                        "if_idx":         0,
                        "is_wireless":    True,
                        "port_mac_count": 1,
                        "in_err": None, "out_err": None,
                        "in_disc": None, "out_disc": None,
                    }
                if not new_entries:
                    log.debug("Bridge scan %s (%s): no client data from AP, skipping",
                              switch_ip, sw_name)
                    return
                log.info("Bridge scan %s (%s): ARP table fallback, %d wireless clients",
                         switch_ip, sw_name, len(new_entries))
    else:
        log.debug("Bridge scan %s (%s): no Bridge MIB, skipping", switch_ip, sw_name)
        return

    # For switch sources, drop trunk/uplink ports (high MAC count = not a direct connection).
    # AP sources skip this filter — every MAC they learn is a direct wireless association.
    # Threshold of 50: AP uplink ports have ~10-20 MACs (bridged wireless clients) and must
    # pass through so the AP device itself is attributed correctly; true switch-to-switch
    # trunk ports have far more MACs and are still filtered.
    _TRUNK_THRESHOLD = 50
    if not is_ap_source:
        new_entries = {mac: e for mac, e in new_entries.items()
                       if e["port_mac_count"] <= _TRUNK_THRESHOLD}

    _wireless_kws = ("ath", "wlan", "wifi", "bss", "vap", "wl", "ra", "mon", "dot11", "ssid", "mbss")

    with _mac_port_lock:
        # Remove stale entries from this switch
        for k in [k for k, v in _mac_to_port.items() if v["switch_ip"] == switch_ip]:
            del _mac_to_port[k]
        # Merge: for MACs already claimed by another device, prefer the most-direct connection.
        # Wireless (AP radio) always beats wired (switch uplink) regardless of scan order.
        # Among same-type entries, prefer the port with fewer MACs (access > uplink).
        for mac, entry in new_entries.items():
            existing = _mac_to_port.get(mac)
            if existing and existing["switch_ip"] != switch_ip:
                ex_if  = (existing.get("if_name") or "").lower()
                new_if = (entry.get("if_name") or "").lower()
                ex_wireless  = existing.get("is_wireless") or any(kw in ex_if  for kw in _wireless_kws)
                new_wireless = entry.get("is_wireless")   or any(kw in new_if for kw in _wireless_kws)
                if ex_wireless and not new_wireless:
                    continue  # existing wireless AP entry beats new wired switch entry
                if not new_wireless and entry["port_mac_count"] >= existing.get("port_mac_count", 1):
                    continue  # both wired: existing is equally or more specific
                # new_wireless=True always overwrites existing wired entry (fall through to store)
            _mac_to_port[mac] = entry

    log.info("Bridge scan %s (%s): %d MACs mapped", switch_ip, sw_name, len(new_entries))
    _save_mac_to_port()

    if is_ap_source:
        snr_map = _aruba_snmp_snr(switch_ip, community, snmp_port)
        if snr_map:
            with _mac_port_lock:
                for mac, data in snr_map.items():
                    if mac in _mac_to_port and _mac_to_port[mac]["switch_ip"] == switch_ip:
                        snr   = data.get("snr")
                        speed = data.get("speed")
                        if snr is not None:
                            _mac_to_port[mac]["snr"] = snr
                            # Aruba Instant does not expose RSSI via SNMP; derive from SNR
                            # using the standard 2.4/5 GHz noise floor of −95 dBm.
                            _mac_to_port[mac]["rssi_est"] = snr - 95
                        if speed is not None:
                            _mac_to_port[mac]["speed"] = speed
            _save_mac_to_port()
            log.debug("Bridge scan %s: %d SNR/speed readings", switch_ip, len(snr_map))


def _aruba_snmp_snr(switch_ip: str, community: str, snmp_port: int = 161) -> dict:
    """Walk Aruba Instant aiClientStatsTable cols 7 (SNR dB) and 11 (TX rate Mbps).
    Returns {mac: {"snr": int|None, "speed": int|None}}."""
    AI_BASE      = "1.3.6.1.4.1.14823.2.3.3.1.2.4.1"
    AI_SNR_COL   = f"{AI_BASE}.7"
    AI_SPEED_COL = f"{AI_BASE}.11"
    base_len = len(AI_SNR_COL.split("."))
    result: dict = {}
    for col_oid, field in ((AI_SNR_COL, "snr"), (AI_SPEED_COL, "speed")):
        for oid_str, val_str in _snmpwalk(switch_ip, community, col_oid, timeout=10, port=snmp_port):
            parts = oid_str.lstrip(".").split(".")
            suffix = parts[base_len:]
            if len(suffix) == 6:
                try:
                    mac = ":".join(f"{int(b):02x}" for b in suffix)
                    if mac not in result:
                        result[mac] = {"snr": None, "speed": None}
                    result[mac][field] = int(_sv(val_str))
                except ValueError:
                    pass
    return result


def _bridge_scan_all() -> None:
    """Run IF-MIB + Bridge MIB scan for every configured SNMP switch/AP."""
    switches = list(SNMP_SWITCHES)
    if not switches:
        return
    log.info("Bridge scan: starting sweep of %d device(s)", len(switches))
    for sw in switches:
        ip        = sw.get("ip", "")
        community = sw.get("community") or SNMP_COMMUNITY
        if not ip:
            continue
        if ip in _SNMP_IF_RUNNING:
            log.debug("Bridge scan: %s already running, skipping", ip)
            continue
        try:
            _run_snmp_if_diag(ip, community)
        except Exception as e:
            log.warning("Bridge scan failed for %s: %s", ip, e)


def _snmp_bridge_scan_loop() -> None:
    """Run a full bridge scan on startup then on the configured interval."""
    time.sleep(15)  # give startup a moment to settle
    while True:
        _bridge_scan_all()
        time.sleep(SNMP_BRIDGE_SCAN_INTERVAL * 60)


def _do_scan(network: str) -> None:
    global _scan_status
    _scan_status = {"state": "running", "message": f"Scanning {network}…"}
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-oX", "-", "--host-timeout", "5s", network],
            capture_output=True, text=True, timeout=180,
        )
        found = _parse_nmap_xml(result.stdout)
        # Drop any discovered IPs not in the scanned subnet (e.g. Docker bridge 172.17.x.x)
        try:
            _scan_net = ipaddress.IPv4Network(network, strict=False)
            found = [d for d in found if ipaddress.IPv4Address(d["ip"]) in _scan_net]
        except Exception:
            pass
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


def _banner_grab(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Return first useful service line from a port banner, or None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            if port in (80, 8080, 8000, 8888, 8123):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            raw = s.recv(512).decode("utf-8", errors="replace")
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                if port in (80, 8080, 8000, 8888, 8123):
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
                    if line.startswith("HTTP/"):
                        continue
                else:
                    return line[:120]
    except Exception:
        pass
    return None


def _der_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    """Return (tag, value_bytes, next_pos) from a DER TLV at pos."""
    if pos + 1 >= len(data):
        raise ValueError("truncated")
    tag = data[pos]; pos += 1
    b   = data[pos]; pos += 1
    if b & 0x80:
        n = b & 0x7f
        if n == 0 or n > 4 or pos + n > len(data):
            raise ValueError("bad length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        length = b
    if pos + length > len(data):
        raise ValueError("data truncated")
    return tag, data[pos:pos + length], pos + length


def _der_oid_str(oid: bytes) -> str:
    """Decode DER OID bytes to dotted string like '2.5.4.3'."""
    if not oid:
        return ""
    parts = [str(oid[0] // 40), str(oid[0] % 40)]
    val = 0
    for b in oid[1:]:
        val = (val << 7) | (b & 0x7f)
        if not (b & 0x80):
            parts.append(str(val)); val = 0
    return ".".join(parts)


def _der_rdn(seq: bytes) -> dict[str, str]:
    """Parse RDNSequence bytes → {OID_dotted: value_str}."""
    out: dict[str, str] = {}
    pos = 0
    while pos < len(seq):
        try:
            tag, set_b, pos = _der_tlv(seq, pos)
            if tag != 0x31:
                continue
            sp = 0
            while sp < len(set_b):
                _, av, sp = _der_tlv(set_b, sp)
                o_tag, o_val, vp = _der_tlv(av, 0)
                if o_tag != 0x06:
                    continue
                _, v_val, _ = _der_tlv(av, vp)
                out[_der_oid_str(o_val)] = v_val.decode("utf-8", errors="replace")
        except Exception:
            break
    return out


_OID_CN  = "2.5.4.3"
_OID_ORG = "2.5.4.10"
_OID_SAN = "2.5.29.17"


def _parse_der_cert(der: bytes) -> dict | None:
    """Parse a DER certificate → {cn, issuer, expiry_iso, days_left, sans}."""
    try:
        _, cert_seq, _ = _der_tlv(der, 0)
        _, tbs, _      = _der_tlv(cert_seq, 0)
        p = 0
        for _ in range(3):
            _, _, p = _der_tlv(tbs, p)          # skip version, serial, sigAlg
        _, issuer_b, p = _der_tlv(tbs, p)
        _, valid_b,  p = _der_tlv(tbs, p)
        _, subj_b,   p = _der_tlv(tbs, p)
        _, _,        p = _der_tlv(tbs, p)       # subjectPublicKeyInfo

        issuer  = _der_rdn(issuer_b)
        subject = _der_rdn(subj_b)

        vp = 0
        _, _, vp       = _der_tlv(valid_b, vp)  # skip notBefore
        na_tag, na_b, _ = _der_tlv(valid_b, vp)
        ts = na_b.decode("ascii", errors="replace")
        if na_tag == 0x17:                       # UTCTime YYMMDDHHMMSSZ
            yy = int(ts[:2]); yr = 2000 + yy if yy < 50 else 1900 + yy
            expiry = datetime(yr, int(ts[2:4]), int(ts[4:6]),
                              int(ts[6:8]), int(ts[8:10]), int(ts[10:12]),
                              tzinfo=timezone.utc)
        else:                                    # GeneralizedTime YYYYMMDDHHMMSSZ
            expiry = datetime(int(ts[:4]), int(ts[4:6]), int(ts[6:8]),
                              int(ts[8:10]), int(ts[10:12]), int(ts[12:14]),
                              tzinfo=timezone.utc)
        days_left = (expiry - datetime.now(timezone.utc)).days

        sans: list[str] = []
        while p < len(tbs):
            try:
                t3, ext_ctx, p = _der_tlv(tbs, p)
                if t3 != 0xa3:
                    continue
                _, exts, _ = _der_tlv(ext_ctx, 0)
                ep = 0
                while ep < len(exts):
                    _, ext, ep = _der_tlv(exts, ep)
                    xp = 0
                    xt, xoid, xp = _der_tlv(ext, xp)
                    if xt != 0x06 or _der_oid_str(xoid) != _OID_SAN:
                        continue
                    if xp < len(ext) and ext[xp] == 0x01:
                        _, _, xp = _der_tlv(ext, xp)  # skip critical bool
                    _, san_oct, _ = _der_tlv(ext, xp)
                    _, gnames, _  = _der_tlv(san_oct, 0)
                    gp = 0
                    while gp < len(gnames):
                        gt, gv, gp = _der_tlv(gnames, gp)
                        if (gt & 0x1f) == 2:
                            try: sans.append(gv.decode("ascii"))
                            except Exception: pass
            except Exception:
                break

        return {
            "cn":        subject.get(_OID_CN),
            "issuer":    issuer.get(_OID_ORG) or issuer.get(_OID_CN),
            "expiry":    expiry.isoformat(),
            "days_left": days_left,
            "sans":      sans[:8],
        }
    except Exception as e:
        log.debug("DER cert parse error: %s", e)
        return None


def _tls_cert(ip: str, port: int, timeout: float = 3.0) -> dict | None:
    """Return TLS certificate details for host:port, or None."""
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                der = s.getpeercert(binary_form=True)
                return _parse_der_cert(der) if der else None
    except Exception:
        return None


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

# ---------------------------------------------------------------------------
# mDNS / Bonjour passive listener
# ---------------------------------------------------------------------------
_mdns_services: dict[str, set] = {}   # ip → set of friendly service label strings
_mdns_lock = threading.Lock()

_MDNS_SERVICE_LABELS: dict[str, str] = {
    "_http._tcp":           "HTTP",
    "_https._tcp":          "HTTPS",
    "_ssh._tcp":            "SSH",
    "_ftp._tcp":            "FTP",
    "_smb._tcp":            "SMB",
    "_afpovertcp._tcp":     "AFP",
    "_nfs._tcp":            "NFS",
    "_hap._tcp":            "HomeKit",
    "_homekit._tcp":        "HomeKit",
    "_googlecast._tcp":     "Chromecast",
    "_airplay._tcp":        "AirPlay",
    "_raop._tcp":           "AirPlay",
    "_printer._tcp":        "Printer",
    "_ipp._tcp":            "Printer",
    "_mqtt._tcp":           "MQTT",
    "_esphomelib._tcp":     "ESPHome",
    "_matter._tcp":         "Matter",
    "_home-assistant._tcp": "HomeAssist",
    "_workstation._tcp":    "Linux",
    "_companion-link._tcp": "Apple",
    "_rdp._tcp":            "RDP",
    "_vnc._tcp":            "VNC",
}


def _dns_name(data: bytes, pos: int) -> tuple[str, int]:
    """Decode a DNS wire-format name with pointer compression."""
    labels: list[str] = []
    end_pos = -1
    visited: set[int] = set()
    while pos < len(data):
        if pos in visited:
            break
        visited.add(pos)
        length = data[pos]
        if length == 0:
            pos += 1
            if end_pos < 0:
                end_pos = pos
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if end_pos < 0:
                end_pos = pos + 2
            pos = ptr
            continue
        pos += 1
        labels.append(data[pos: pos + length].decode("utf-8", errors="replace"))
        pos += length
    return ".".join(labels), (end_pos if end_pos >= 0 else pos)


def _dns_records(data: bytes) -> list[dict]:
    """Parse answer + additional records from a DNS/mDNS packet."""
    if len(data) < 12:
        return []
    qdcount = (data[4] << 8) | data[5]
    ancount = (data[6] << 8) | data[7]
    arcount = (data[10] << 8) | data[11]
    pos = 12
    for _ in range(qdcount):
        try:
            _, pos = _dns_name(data, pos)
            pos += 4
        except Exception:
            return []
    records: list[dict] = []
    for _ in range(ancount + arcount):
        if pos + 10 > len(data):
            break
        try:
            name, pos = _dns_name(data, pos)
            rtype     = (data[pos] << 8) | data[pos + 1]
            rdlen     = (data[pos + 8] << 8) | data[pos + 9]
            rdata_pos = pos + 10
            rdata     = data[rdata_pos: rdata_pos + rdlen]
            pos       = rdata_pos + rdlen
            records.append({"name": name, "type": rtype, "rdata": rdata,
                            "rdata_pos": rdata_pos, "pkt": data})
        except Exception:
            break
    return records


def _mdns_listen_loop() -> None:
    """Passive mDNS listener — accumulates service announcements in _mdns_services."""
    MDNS_ADDR = "224.0.0.251"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        sock.bind(("", 5353))
        mreq = socket.inet_aton(MDNS_ADDR) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(2.0)
        log.info("mDNS listener started on 224.0.0.251:5353")
    except Exception as e:
        log.warning("mDNS listener could not bind (mDNS discovery disabled): %s", e)
        return

    while True:
        try:
            pkt, (src_ip, _) = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception:
            continue
        try:
            recs = _dns_records(pkt)
            host_ip: dict[str, str] = {}
            for r in recs:
                if r["type"] == 1 and len(r["rdata"]) == 4:
                    host_ip[r["name"].rstrip(".")] = ".".join(str(b) for b in r["rdata"])
            srv_host: dict[str, str] = {}
            for r in recs:
                if r["type"] == 33 and len(r["rdata"]) >= 7:
                    h, _ = _dns_name(r["pkt"], r["rdata_pos"] + 6)
                    srv_host[r["name"].rstrip(".")] = h.rstrip(".")
            for r in recs:
                if r["type"] != 12:
                    continue
                svc_type = r["name"].rstrip(".")
                instance, _ = _dns_name(r["pkt"], r["rdata_pos"])
                instance = instance.rstrip(".")
                target = host_ip.get(srv_host.get(instance, ""), src_ip)
                if not target or target.startswith("169.254"):
                    continue
                for key, label in _MDNS_SERVICE_LABELS.items():
                    if key in svc_type:
                        with _mdns_lock:
                            _mdns_services.setdefault(target, set()).add(label)
                        break
        except Exception as e:
            log.debug("mDNS parse from %s: %s", src_ip, e)


def _probe_device_features_once(ip: str, device: dict) -> dict:
    """Run SNMP + ONVIF probes; derive protocol tags from known open ports."""
    features: dict = dict(device.get("features") or {})

    # SNMP — rich info dict or None if no response
    snmp_info = _snmp_probe(ip, SNMP_COMMUNITY)
    features["snmp"]      = snmp_info is not None
    features["snmp_info"] = snmp_info or {}

    # ONVIF camera check
    features["onvif"] = _onvif_probe(ip)

    # Protocol tags from already-monitored open ports (zero extra probes)
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

    if "RTSP" not in seen and _check_port(ip, 554, timeout=2.0):
        protocols.append("RTSP")

    features["protocols"] = sorted(protocols)

    # Banner grab from open ports
    _BANNER_PORTS = {21, 22, 23, 25, 80, 8080, 8000, 8888, 8123}
    banners: dict[str, str] = {}
    for port_str, is_open in port_status.items():
        p = int(port_str)
        if is_open and p in _BANNER_PORTS:
            b = _banner_grab(ip, p)
            if b:
                banners[port_str] = b
    features["banners"] = banners

    # TLS certificate inspection on HTTPS ports
    certs: dict[str, dict] = {}
    for port_str, is_open in port_status.items():
        p = int(port_str)
        if is_open and p in (443, 8443):
            cert = _tls_cert(ip, p)
            if cert:
                certs[port_str] = cert
    features["tls_certs"] = certs

    # mDNS services accumulated by passive listener
    with _mdns_lock:
        features["mdns"] = sorted(_mdns_services.get(ip, set()))

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
            if not _devices[ip].get("ports"):
                _devices[ip]["ports"] = ports
                log.info("Updated seed ports for %s: %s", ip, ports)
        _save_devices()

# ---------------------------------------------------------------------------
# Uptime history (in-memory ring buffer — not persisted, resets on restart)
# ---------------------------------------------------------------------------
_device_history: dict[str, list] = {}  # ip -> [{ts: float, up: bool}, ...]
_HISTORY_TTL = 90_000  # keep 25 h so the 24 h window is always fully populated


def _record_history(ip: str, up: bool, latency: float | None = None) -> None:
    now  = time.time()
    hist = _device_history.setdefault(ip, [])
    hist.append({"ts": now, "up": up, "ms": latency})
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
    """Return bucketed availability and latency arrays for the device detail page."""
    hist = _device_history.get(ip, [])
    now  = time.time()
    def _avail(window: float, n: int) -> list:
        size = window / n
        result = []
        for i in range(n):
            t_end   = now - (n - 1 - i) * size
            t_start = t_end - size
            samples = [e["up"] for e in hist if t_start <= e["ts"] < t_end]
            result.append(round(100 * sum(samples) / len(samples)) if samples else None)
        return result
    def _lat(window: float, n: int) -> list:
        size = window / n
        result = []
        for i in range(n):
            t_end   = now - (n - 1 - i) * size
            t_start = t_end - size
            samples = [e["ms"] for e in hist
                       if t_start <= e["ts"] < t_end and e.get("up") and e.get("ms") is not None]
            result.append(round(sum(samples) / len(samples), 1) if samples else None)
        return result
    return {
        "h1":     _avail(3600,  30),   # 1 h  → 30 × 2-min buckets
        "h24":    _avail(86400, 48),   # 24 h → 48 × 30-min buckets
        "lat_h1": _lat(3600,  30),
        "lat_h24":_lat(86400, 48),
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
        _record_history(ip, up, latency)
        label = dev.get("name") or dev.get("hostname") or ip
        mode  = dev.get("alert_mode") or "default"
        log.debug("monitored %s (%s): %s", label, ip, "up" if up else "down")
        if prev == "up" and not up:
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
                if prev_up is True and not port_up:
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
        with _db_conn() as conn:
            row = conn.execute("SELECT value FROM kv WHERE key='snmp_devices'").fetchone()
        if row:
            return json.loads(row["value"])
    except Exception as e:
        log.warning("DB load snmp_devices failed: %s", e)
    # migrate from JSON
    try:
        with open(_SNMP_DEVICES_PATH) as fh:
            data = json.load(fh)
        if data:
            log.info("Migrating %d SNMP devices from JSON to SQLite", len(data))
            with _db_conn() as conn:
                conn.execute("INSERT OR REPLACE INTO kv (key, value) VALUES ('snmp_devices', ?)",
                             (json.dumps(data),))
        return data
    except Exception:
        return []

def _save_snmp_devices() -> None:
    try:
        with _db_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO kv (key, value) VALUES ('snmp_devices', ?)",
                         (json.dumps(_snmp_devices),))
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
        with _db_conn() as conn:
            rows = conn.execute("SELECT oui, vendor FROM mac_vendors").fetchall()
        if rows:
            _mac_vendor_cache = {r["oui"]: r["vendor"] for r in rows}
            return
    except Exception as e:
        log.warning("DB load mac_vendors failed: %s", e)
    # migrate from JSON
    try:
        with open(_MAC_VENDOR_CACHE_PATH) as fh:
            _mac_vendor_cache = json.load(fh)
        if _mac_vendor_cache:
            log.info("Migrating %d MAC vendors from JSON to SQLite", len(_mac_vendor_cache))
            _save_mac_vendor_cache()
    except Exception:
        _mac_vendor_cache = {}

def _save_mac_vendor_cache() -> None:
    try:
        rows = list(_mac_vendor_cache.items())
        with _db_conn() as conn:
            conn.executemany("INSERT OR REPLACE INTO mac_vendors (oui, vendor) VALUES (?, ?)", rows)
    except Exception as e:
        log.warning("Failed to save mac_vendor_cache: %s", e)

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

def _snmpset(host: str, community: str, oid: str, type_char: str, value: str, port: int = 161, timeout: int = 10) -> bool:
    """Run snmpset -v2c. type_char is i/u/s/etc. Returns True on success."""
    try:
        target = f"{host}:{port}" if port != 161 else host
        r = subprocess.run(
            ["snmpset", "-v2c", "-c", community, target, oid, type_char, value],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode != 0:
            log.warning("snmpset %s [%s=%s]: %s", host, oid, value, r.stderr.strip() or r.stdout.strip())
        return r.returncode == 0
    except FileNotFoundError:
        log.warning("snmpset not found — install the snmp package")
        return False
    except Exception as e:
        log.warning("snmpset %s [%s]: %s", host, oid, e)
        return False


def _snmp_community_for(switch_ip: str) -> str:
    sw = next((s for s in SNMP_SWITCHES if s.get("ip") == switch_ip), None)
    return (sw.get("community") if sw else None) or SNMP_COMMUNITY


def _snmp_port_for(switch_ip: str) -> int:
    sw = next((s for s in SNMP_SWITCHES if s.get("ip") == switch_ip), None)
    return int(sw["port"]) if sw and sw.get("port") else 161


IF_ADMIN_STATUS_OID = "1.3.6.1.2.1.2.2.1.7"  # ifAdminStatus.{ifIndex}: 1=up, 2=down


def _do_bounce(switch_ip: str, if_idx: int, community: str, snmp_port: int) -> None:
    oid = f"{IF_ADMIN_STATUS_OID}.{if_idx}"
    log.info("Port bounce %s if%d — setting down", switch_ip, if_idx)
    _snmpset(switch_ip, community, oid, "i", "2", port=snmp_port)
    time.sleep(4)
    log.info("Port bounce %s if%d — setting up", switch_ip, if_idx)
    _snmpset(switch_ip, community, oid, "i", "1", port=snmp_port)
    log.info("Port bounce %s if%d — complete", switch_ip, if_idx)


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

def _check_new_device(ip: str, mac: str, vendor: str, hostname: str, source: str) -> None:
    if not new_device_alerts or ip in _seen_device_ips:
        return
    _seen_device_ips.add(ip)
    label = hostname or vendor or mac or ip
    maybe_alert(
        f"new_device_{ip}",
        f"New device: {label}",
        f"{ip} ({mac}) — {vendor or 'unknown vendor'} first seen via {source}",
    )


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
                    _check_new_device(ip, mac, vendor, "", name)
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

_meraki_net_devs: dict  = {}   # device name → "ap" | "gateway" | "switch" | "other"
_meraki_net_macs: dict  = {}   # mac (lower) → {name, model, type, serial}
_meraki_topology: dict  = {}   # raw link-layer topology {nodes, links} or {}
_meraki_ipam_cache: dict = {"subnets": [], "fixed": {}, "ts": 0}
_meraki_ipam_lock = threading.Lock()

def _meraki_dev_type(model: str) -> str:
    m = (model or "").upper()
    if m.startswith("MR"):                    return "ap"
    if m.startswith("MX") or m.startswith("Z"): return "gateway"
    if m.startswith("MS"):                    return "switch"
    return "other"

def _fmt_wifi_cap(cap: str) -> str:
    """Map wirelessCapabilities string to short WiFi generation label."""
    if not cap:
        return ""
    _gen = {"802.11be": "WiFi 7", "802.11ax": "WiFi 6", "802.11ac": "WiFi 5",
            "802.11n": "WiFi 4", "802.11g": "WiFi 3", "802.11b": "WiFi 1"}
    for std, label in _gen.items():
        if std in cap:
            return label
    return cap.split(" - ")[0] if " - " in cap else cap


def _poll_meraki_api_clients() -> int:
    """Fetch clients from Meraki Dashboard API; enrich _devices with MAC/vendor/hostname."""
    global _meraki_net_devs, _meraki_net_macs, _meraki_topology
    key     = MERAKI_API_KEY
    net_id  = MERAKI_NETWORK_ID
    if not key or not net_id:
        return 0

    # Fetch network devices so we can classify by model (MR=AP, MX=gateway, MS=switch)
    net_devs = _meraki_api_get(f"/networks/{net_id}/devices", key) or []
    _meraki_net_devs = {d.get("name", ""): _meraki_dev_type(d.get("model", ""))
                        for d in net_devs if d.get("name")}
    _meraki_net_macs = {(d.get("mac") or "").lower(): {
        "name":   d.get("name", ""),
        "model":  d.get("model", ""),
        "type":   _meraki_dev_type(d.get("model", "")),
        "serial": d.get("serial", ""),
        "ip":     d.get("lanIp") or d.get("wan1Ip") or "",
    } for d in net_devs if d.get("mac")}

    # Fetch physical link-layer topology (best-effort — not all firmware versions expose this)
    topo = _meraki_api_get(f"/networks/{net_id}/topology/linkLayer", key)
    _meraki_topology = topo if isinstance(topo, dict) else {}

    clients = _meraki_api_get(f"/networks/{net_id}/clients", key, {"timespan": 86400, "perPage": 1000})
    if not clients:
        return 0
    updated = 0
    wireless_sig_queue: list = []   # (meraki_client_id, device_ip) for wireless clients
    for c in clients:
        ip  = c.get("ip") or ""
        mac = (c.get("mac") or "").lower()
        if not ip or not mac:
            continue
        vendor     = c.get("manufacturer") or ""
        hostname   = c.get("description") or ""
        dhcp_name  = c.get("dhcpHostname") or ""
        connection = c.get("recentDeviceName") or ""
        ssid       = c.get("ssid") or ""
        sw_port    = c.get("switchport") or ""
        conn_type  = (c.get("recentDeviceConnection") or "").lower()
        wired      = conn_type == "wired" or (bool(sw_port) and not ssid)
        online     = (c.get("status") or "").lower() == "online"
        rssi_v    = c.get("rssi")   # null in clients list; fetched separately below
        snr_v     = c.get("snr")    # null in clients list; fetched separately below
        wifi_cap  = c.get("wirelessCapabilities") or ""
        meraki_id = c.get("id") or ""
        if not wired and meraki_id and ip:
            wireless_sig_queue.append((meraki_id, ip))
        with _devices_lock:
            if ip not in _devices:
                _devices[ip] = {
                    "ip": ip, "mac": mac, "vendor": vendor,
                    "hostname": hostname, "name": "",
                    "dhcp_hostname": dhcp_name,
                    "meraki_connection": connection,
                    "meraki_ssid": ssid,
                    "meraki_port": sw_port,
                    "meraki_wired": wired,
                    "meraki_rssi":    rssi_v,
                    "meraki_snr":     snr_v,
                    "meraki_wifi_cap": wifi_cap,
                    "learned_from": "Meraki API",
                    "meraki_status": "online" if online else "offline",
                    "meraki_product": "",
                    "monitored": False, "alert_mode": "default", "status": "unknown",
                    "last_seen": None, "ping_latency_ms": None,
                    "ports": [], "port_status": {},
                }
                _check_new_device(ip, mac, vendor, hostname or dhcp_name, "Meraki API")
                log.info("Meraki API discovered %s — %s (%s)", ip, mac, vendor or "unknown")
                updated += 1
            else:
                d = _devices[ip]
                changed = False
                if mac and not d.get("mac"):
                    _devices[ip]["mac"] = mac;          changed = True
                if vendor and not d.get("vendor"):
                    _devices[ip]["vendor"] = vendor;    changed = True
                if hostname and not d.get("hostname"):
                    _devices[ip]["hostname"] = hostname; changed = True
                if dhcp_name:
                    _devices[ip]["dhcp_hostname"]   = dhcp_name;  changed = True
                if connection:
                    _devices[ip]["meraki_connection"] = connection; changed = True
                if ssid:
                    _devices[ip]["meraki_ssid"] = ssid; changed = True
                if sw_port:
                    _devices[ip]["meraki_port"] = sw_port; changed = True
                _devices[ip]["meraki_wired"] = wired; changed = True
                if rssi_v  is not None:  _devices[ip]["meraki_rssi"]     = rssi_v;  changed = True
                if snr_v   is not None:  _devices[ip]["meraki_snr"]      = snr_v;   changed = True
                if wifi_cap:             _devices[ip]["meraki_wifi_cap"] = wifi_cap; changed = True
                ms = "online" if online else "offline"
                if d.get("meraki_status") != ms:
                    _devices[ip]["meraki_status"] = ms; changed = True
                if not d.get("learned_from"):
                    _devices[ip]["learned_from"] = "Meraki API"; changed = True
                if changed:
                    updated += 1
        _save_devices()

    # Fetch per-client signal quality history and connection stats for wireless clients.
    # The /networks/.../clients list always returns rssi/snr/txRate as null;
    # real values come from dedicated per-client endpoints.
    if wireless_sig_queue:
        import time as _t
        now = int(_t.time())
        sig_params = {"resolution": 300, "t0": now - 1800, "t1": now}
        sig_updated = 0
        for meraki_id, dev_ip in wireless_sig_queue:
            sig = _meraki_api_get(
                f"/networks/{net_id}/wireless/signalQualityHistory",
                key, {**sig_params, "clientId": meraki_id},
            )
            if sig and isinstance(sig, list):
                latest = sig[-1]
                rssi = latest.get("rssi")
                snr  = latest.get("snr")
                with _devices_lock:
                    if dev_ip in _devices:
                        if rssi is not None: _devices[dev_ip]["meraki_rssi"] = rssi
                        if snr  is not None: _devices[dev_ip]["meraki_snr"]  = snr
                        sig_updated += 1

            rate = _meraki_api_get(
                f"/networks/{net_id}/wireless/dataRateHistory",
                key, {**sig_params, "clientId": meraki_id},
            )
            if rate and isinstance(rate, list):
                latest_r = rate[-1]
                dl_kbps = latest_r.get("downloadKbps")
                if dl_kbps:
                    with _devices_lock:
                        if dev_ip in _devices:
                            _devices[dev_ip]["meraki_speed"] = round(dl_kbps / 1000)

        if sig_updated:
            with _devices_lock:
                _save_devices()
        log.info("Meraki API: %d wireless signal records fetched", sig_updated)

    log.info("Meraki API: %d clients, %d updated", len(clients), updated)
    return updated

def _poll_meraki_ipam() -> None:
    """Fetch VLAN/subnet config, fixed IP assignments, and reserved ranges from Meraki."""
    global _meraki_ipam_cache
    key    = MERAKI_API_KEY
    net_id = MERAKI_NETWORK_ID
    if not key or not net_id:
        return

    vlans = _meraki_api_get(f"/networks/{net_id}/appliance/vlans", key)
    subnets: list = []
    fixed:   dict = {}   # ip → {mac, name, vlan_id, vlan_name}

    if isinstance(vlans, list) and vlans:
        for v in vlans:
            subnet_cidr = v.get("subnet", "")
            if not subnet_cidr:
                continue
            fixed_raw = v.get("fixedIpAssignments") or {}
            reserved  = v.get("reservedIpRanges") or []
            subnets.append({
                "id":              v.get("id"),
                "name":            v.get("name", ""),
                "subnet":          subnet_cidr,
                "gateway":         v.get("applianceIp", ""),
                "dhcp_mode":       v.get("dhcpHandling", ""),
                "dhcp_lease_time": v.get("dhcpLeaseTime", ""),
                "reserved_ranges": reserved,
            })
            for mac, info in fixed_raw.items():
                ip = info.get("ip", "")
                if ip:
                    fixed[ip] = {
                        "mac":       mac.lower(),
                        "name":      info.get("name", ""),
                        "vlan_id":   v.get("id"),
                        "vlan_name": v.get("name", ""),
                    }
    else:
        # VLANs disabled — fall back to single LAN
        single = _meraki_api_get(f"/networks/{net_id}/appliance/singleLan", key)
        if isinstance(single, dict) and single.get("subnet"):
            fixed_raw = single.get("fixedIpAssignments") or {}
            reserved  = single.get("reservedIpRanges") or []
            subnets.append({
                "id":              1,
                "name":            "LAN",
                "subnet":          single.get("subnet", ""),
                "gateway":         single.get("applianceIp", ""),
                "dhcp_mode":       single.get("dhcpHandling", ""),
                "dhcp_lease_time": "",
                "reserved_ranges": reserved,
            })
            for mac, info in fixed_raw.items():
                ip = info.get("ip", "")
                if ip:
                    fixed[ip] = {
                        "mac":       mac.lower(),
                        "name":      info.get("name", ""),
                        "vlan_id":   1,
                        "vlan_name": "LAN",
                    }
        elif single is None:
            log.warning("IPAM: could not fetch VLAN or single-LAN config for network %s", net_id)

    with _meraki_ipam_lock:
        _meraki_ipam_cache = {"subnets": subnets, "fixed": fixed, "ts": time.time()}
    log.info("IPAM: %d subnets, %d fixed assignments", len(subnets), len(fixed))


def _meraki_api_poller_loop() -> None:
    while True:
        try:
            if MERAKI_API_KEY and MERAKI_NETWORK_ID:
                _poll_meraki_api_clients()
                _poll_meraki_ipam()
        except Exception as e:
            log.exception("Meraki API poll error: %s", e)
        time.sleep(MERAKI_POLL_INTERVAL)

# ---------------------------------------------------------------------------
# Aruba Central API
# ---------------------------------------------------------------------------
ARUBA_CENTRAL_API_URL:   str = ""   # e.g. https://apigw-prod2.central.arubanetworks.com
ARUBA_CENTRAL_API_TOKEN: str = ""   # Access token (long-lived) from Central API Gateway
ARUBA_CENTRAL_POLL_INTERVAL: int = 300  # seconds

def _aruba_central_get(path: str, token: str, base: str,
                        params: dict | None = None) -> list | dict | None:
    try:
        resp = requests.get(
            f"{base.rstrip('/')}{path}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            params=params or {},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        log.warning("Aruba Central %s → %d: %s", path, resp.status_code, resp.text[:200])
    except Exception as e:
        log.warning("Aruba Central %s failed: %s", path, e)
    return None

def _poll_aruba_central_clients() -> int:
    base  = ARUBA_CENTRAL_API_URL
    token = ARUBA_CENTRAL_API_TOKEN
    if not base or not token:
        return 0
    # Fetch all clients (wireless and wired), paginated
    all_clients: list = []
    offset = 0
    limit  = 1000
    while True:
        resp = _aruba_central_get("/monitoring/v2/clients", token, base,
                                   {"calculate_total": "true", "limit": limit, "offset": offset})
        if not resp:
            break
        batch = resp.get("clients") or []
        all_clients.extend(batch)
        if len(batch) < limit:
            break
        offset += limit

    if not all_clients:
        log.debug("Aruba Central: no clients returned")
        return 0

    updated = 0
    for c in all_clients:
        ip  = c.get("ip_address") or ""
        mac = (c.get("macaddr") or "").lower().replace("-", ":")
        if not ip or not mac:
            continue
        ap_name  = c.get("associated_device") or c.get("associated_device_name") or ""
        ssid     = c.get("network") or c.get("ssid") or ""
        wired    = (c.get("client_type") or c.get("connection") or "").lower() == "wired"
        hostname = c.get("name") or c.get("hostname") or ""
        vendor   = c.get("manufacturer") or ""
        with _devices_lock:
            if ip not in _devices:
                _devices[ip] = {
                    "ip": ip, "mac": mac, "vendor": vendor,
                    "hostname": hostname, "name": "",
                    "aruba_connection": ap_name,
                    "aruba_ssid": ssid,
                    "aruba_wired": wired,
                    "learned_from": "Aruba Central",
                    "monitored": False, "alert_mode": "default", "status": "unknown",
                    "last_seen": None, "ping_latency_ms": None,
                    "ports": [], "port_status": {},
                }
                _check_new_device(ip, mac, vendor, hostname, "Aruba Central")
                log.info("Aruba Central discovered %s — %s (%s)", ip, mac, vendor or "unknown")
                updated += 1
            else:
                d = _devices[ip]
                changed = False
                if mac and not d.get("mac"):       _devices[ip]["mac"] = mac;           changed = True
                if vendor and not d.get("vendor"): _devices[ip]["vendor"] = vendor;     changed = True
                if hostname and not d.get("hostname"): _devices[ip]["hostname"] = hostname; changed = True
                if ap_name: _devices[ip]["aruba_connection"] = ap_name; changed = True
                if ssid:    _devices[ip]["aruba_ssid"]       = ssid;    changed = True
                _devices[ip]["aruba_wired"] = wired;                                    changed = True
                if not d.get("learned_from"): _devices[ip]["learned_from"] = "Aruba Central"; changed = True
                if changed:
                    updated += 1
        _save_devices()
    log.info("Aruba Central: %d clients, %d updated", len(all_clients), updated)
    return updated

def _aruba_central_poller_loop() -> None:
    while True:
        try:
            if ARUBA_CENTRAL_API_URL and ARUBA_CENTRAL_API_TOKEN:
                _poll_aruba_central_clients()
        except Exception as e:
            log.exception("Aruba Central poll error: %s", e)
        time.sleep(ARUBA_CENTRAL_POLL_INTERVAL)

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
    "new_device_alerts":      {"label": "Alert on new device",             "default": "false"},
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
    # Aruba Central API
    "aruba_central_api_url":   {"label": "Aruba Central API URL",          "default": ""},
    "aruba_central_api_token": {"label": "Aruba Central access token",     "default": "", "secret": True},
    "aruba_central_poll_interval": {"label": "Aruba Central poll interval (s)", "default": "300"},
    # Network scan
    "scan_ports":             {"label": "Port scan list (comma-separated)", "default": "22,80,443,8080,8123,1883,8883"},
    "snmp_community":         {"label": "SNMP community string",            "default": "public"},
    "snmp_switches":          {"label": "SNMP switches (JSON list)",        "default": "[]"},
    "snmp_bridge_scan_interval": {"label": "Bridge scan interval (minutes)", "default": "60"},
    # Polling intervals
    "poll_interval":          {"label": "Device ping interval (s)",         "default": str(POLL_INTERVAL)},
    "ha_poll_interval":       {"label": "HA add-on poll interval (s)",      "default": str(HA_POLL_INTERVAL)},
    "meraki_poll_interval":   {"label": "Meraki API poll interval (s)",     "default": str(MERAKI_POLL_INTERVAL)},
    # Sync
    "peer_url":               {"label": "Peer instance URL",               "default": ""},
    "alert_role":             {"label": "Alert role",                      "default": "standalone"},
    "auto_sync_peer":         {"label": "Auto-sync to peer on change",     "default": "false"},
    # Vulnerability scanning — general
    "vuln_auto_scan_enabled":       {"label": "Auto-scan enabled",                  "default": "true"},
    "vuln_auto_scan_interval":      {"label": "Auto-scan interval (hours)",          "default": "24"},
    "vuln_scan_delay":              {"label": "Delay between hosts in sweep (s)",   "default": "15"},
    "vuln_concurrency":             {"label": "Max concurrent scans",               "default": "2"},
    "vuln_exclude_ips":             {"label": "Exclude IPs (comma-separated)",      "default": ""},
    "vuln_scan_on_new_device":      {"label": "Scan on new device discovery",       "default": "false"},
    # Vulnerability scanning — nmap
    "vuln_nmap_enabled":            {"label": "nmap phase enabled",                 "default": "true"},
    "vuln_nmap_timing":             {"label": "nmap timing template (T0–T5)",       "default": "T4"},
    "vuln_nmap_scripts":            {"label": "nmap scripts",                       "default": "vuln"},
    "vuln_nmap_ports":              {"label": "nmap port range (empty=default)",    "default": ""},
    # Vulnerability scanning — Nuclei
    "vuln_nuclei_enabled":          {"label": "Nuclei phase enabled",               "default": "true"},
    "vuln_nuclei_tags":             {"label": "Nuclei tag filter (empty = all)",    "default": ""},
    "vuln_nuclei_exclude_tags":     {"label": "Nuclei exclude tags",                "default": ""},
    "vuln_nuclei_severity":         {"label": "Nuclei severity filter",             "default": "critical,high,medium,low,info"},
    "vuln_nuclei_rate_limit":       {"label": "Nuclei rate limit (req/s)",          "default": "50"},
    "vuln_nuclei_timeout":          {"label": "Nuclei request timeout (s)",         "default": "10"},
    "vuln_nuclei_concurrency":      {"label": "Nuclei template concurrency",        "default": "25"},
    "vuln_nuclei_bulk_size":        {"label": "Nuclei bulk size (hosts/batch)",     "default": "25"},
    "vuln_nuclei_retries":          {"label": "Nuclei retries",                     "default": "1"},
    "vuln_nuclei_max_host_errors":  {"label": "Nuclei max host errors",             "default": "30"},
    "vuln_nuclei_interactsh":       {"label": "Nuclei interactsh (OOB)",            "default": "false"},
    "vuln_nuclei_headless":         {"label": "Nuclei headless browser mode",       "default": "false"},
    "vuln_nuclei_custom_templates": {"label": "Nuclei extra templates path",        "default": ""},
}

def _load_config() -> dict:
    try:
        with _db_conn() as conn:
            row = conn.execute("SELECT value FROM kv WHERE key='config'").fetchone()
        if row:
            return json.loads(row["value"])
    except Exception as e:
        log.warning("DB load config failed: %s", e)
    # migrate from JSON
    try:
        with open(_CONFIG_PATH) as fh:
            data = json.load(fh)
        if data:
            log.info("Migrating config from JSON to SQLite")
            _save_config(data)
        return data
    except Exception:
        return {}

def _save_config(data: dict) -> None:
    try:
        with _db_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO kv (key, value) VALUES ('config', ?)",
                         (json.dumps(data),))
    except Exception as e:
        log.error("Failed to save config: %s", e)

push_alerts_enabled:  bool = True
push_critical:        bool = True
email_alerts_enabled: bool = False
ALERT_TITLE:          str  = "Farol"
notify_recovery:      bool = False
new_device_alerts:    bool = False
MERAKI_API_KEY:       str  = ""
MERAKI_NETWORK_ID:    str  = ""
ARUBA_CENTRAL_API_URL:       str = ""
ARUBA_CENTRAL_API_TOKEN:     str = ""
ARUBA_CENTRAL_POLL_INTERVAL: int = 300
PEER_URL:             str  = ""
ALERT_ROLE:           str  = "standalone"  # standalone | primary | secondary
AUTO_SYNC_PEER:       bool = False
SNMP_COMMUNITY:            str  = "public"
SNMP_SWITCHES:             list = []   # [{"name": str, "ip": str, "port": int, "community": str}]
SNMP_BRIDGE_SCAN_INTERVAL: int  = 60  # minutes between automatic bridge scans

_peer_reachable:      bool = True   # updated by _peer_health_loop
_peer_fail_streak:    int  = 0
_peer_ok_streak:      int  = 0

def _apply_config(data: dict) -> None:
    global HA_URL, HA_TOKEN
    global NOTIFY_SERVICE, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
    global EMAIL_FROM, EMAIL_FROM_NAME, EMAIL_TO, ALERT_COOLDOWN, push_alerts_enabled, push_critical, email_alerts_enabled
    global ALERT_TITLE, notify_recovery, new_device_alerts, MERAKI_API_KEY, MERAKI_NETWORK_ID, SCAN_PORTS, PEER_URL, ALERT_ROLE, AUTO_SYNC_PEER, SNMP_COMMUNITY, SNMP_SWITCHES, SNMP_BRIDGE_SCAN_INTERVAL
    global ARUBA_CENTRAL_API_URL, ARUBA_CENTRAL_API_TOKEN, ARUBA_CENTRAL_POLL_INTERVAL
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
    if "new_device_alerts"    in data: new_device_alerts    = str(data["new_device_alerts"]).lower() in ("true", "1", "yes")
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
    if "aruba_central_api_url"   in data: ARUBA_CENTRAL_API_URL   = data["aruba_central_api_url"]   or ""
    if "aruba_central_api_token" in data: ARUBA_CENTRAL_API_TOKEN = data["aruba_central_api_token"] or ""
    if "aruba_central_poll_interval" in data: ARUBA_CENTRAL_POLL_INTERVAL = int(data["aruba_central_poll_interval"] or 300)
    if "scan_ports"             in data: SCAN_PORTS             = data["scan_ports"]             or ""
    if "poll_interval"          in data: POLL_INTERVAL          = int(data["poll_interval"]        or 30)
    if "ha_poll_interval"       in data: HA_POLL_INTERVAL       = int(data["ha_poll_interval"]     or 30)
    if "meraki_poll_interval"   in data: MERAKI_POLL_INTERVAL   = int(data["meraki_poll_interval"] or 300)
    if "peer_url"               in data: PEER_URL               = data["peer_url"]                 or ""
    if "alert_role"             in data: ALERT_ROLE             = data["alert_role"]               or "standalone"
    if "auto_sync_peer"         in data: AUTO_SYNC_PEER         = str(data["auto_sync_peer"]).lower() in ("true", "1", "yes")
    if "snmp_community"         in data: SNMP_COMMUNITY         = data["snmp_community"] or "public"
    if "snmp_switches"          in data:
        try:
            parsed = json.loads(data["snmp_switches"] or "[]")
            if isinstance(parsed, list):
                SNMP_SWITCHES = parsed
        except Exception:
            pass
    if "snmp_bridge_scan_interval" in data:
        SNMP_BRIDGE_SCAN_INTERVAL = max(1, int(data["snmp_bridge_scan_interval"] or 60))

    # Vulnerability scanning
    global VULN_AUTO_SCAN_ENABLED, VULN_AUTO_SCAN_INTERVAL, VULN_SCAN_DELAY, VULN_CONCURRENCY
    global VULN_EXCLUDE_IPS, VULN_SCAN_ON_NEW_DEVICE
    global VULN_NMAP_ENABLED, VULN_NMAP_TIMING, VULN_NMAP_SCRIPTS, VULN_NMAP_PORTS
    global VULN_NUCLEI_ENABLED, VULN_NUCLEI_TAGS, VULN_NUCLEI_EXCLUDE_TAGS, VULN_NUCLEI_SEVERITY
    global VULN_NUCLEI_RATE_LIMIT, VULN_NUCLEI_TIMEOUT, VULN_NUCLEI_CONCURRENCY
    global VULN_NUCLEI_BULK_SIZE, VULN_NUCLEI_RETRIES, VULN_NUCLEI_MAX_HOST_ERRORS
    global VULN_NUCLEI_INTERACTSH, VULN_NUCLEI_HEADLESS, VULN_NUCLEI_CUSTOM_TEMPLATES

    def _b(k): return str(data.get(k, "")).lower() in ("true", "1", "yes")
    def _i(k, d):
        try: return int(data[k]) if k in data else d
        except (ValueError, TypeError): return d

    if "vuln_auto_scan_enabled"       in data: VULN_AUTO_SCAN_ENABLED       = _b("vuln_auto_scan_enabled")
    if "vuln_auto_scan_interval"      in data: VULN_AUTO_SCAN_INTERVAL      = _i("vuln_auto_scan_interval", 24)
    if "vuln_scan_delay"              in data: VULN_SCAN_DELAY              = _i("vuln_scan_delay", 15)
    if "vuln_concurrency" in data:
        VULN_CONCURRENCY = _i("vuln_concurrency", 2)
        global _vuln_sem
        _vuln_sem = threading.Semaphore(VULN_CONCURRENCY)
    if "vuln_exclude_ips"             in data:
        raw = data.get("vuln_exclude_ips") or ""
        VULN_EXCLUDE_IPS = {s.strip() for s in raw.split(",") if s.strip()}
    if "vuln_scan_on_new_device"      in data: VULN_SCAN_ON_NEW_DEVICE      = _b("vuln_scan_on_new_device")
    if "vuln_nmap_enabled"            in data: VULN_NMAP_ENABLED            = _b("vuln_nmap_enabled")
    if "vuln_nmap_timing"             in data: VULN_NMAP_TIMING             = data["vuln_nmap_timing"]             or "T4"
    if "vuln_nmap_scripts"            in data: VULN_NMAP_SCRIPTS            = data["vuln_nmap_scripts"]            or "vuln"
    if "vuln_nmap_ports"              in data: VULN_NMAP_PORTS              = data["vuln_nmap_ports"]              or ""
    if "vuln_nuclei_enabled"          in data: VULN_NUCLEI_ENABLED          = _b("vuln_nuclei_enabled")
    if "vuln_nuclei_tags"             in data: VULN_NUCLEI_TAGS             = data["vuln_nuclei_tags"]             or ""
    if "vuln_nuclei_exclude_tags"     in data: VULN_NUCLEI_EXCLUDE_TAGS     = data["vuln_nuclei_exclude_tags"]     or ""
    if "vuln_nuclei_severity"         in data: VULN_NUCLEI_SEVERITY         = data["vuln_nuclei_severity"]         or "critical,high,medium,low,info"
    if "vuln_nuclei_rate_limit"       in data: VULN_NUCLEI_RATE_LIMIT       = _i("vuln_nuclei_rate_limit", 50)
    if "vuln_nuclei_timeout"          in data: VULN_NUCLEI_TIMEOUT          = _i("vuln_nuclei_timeout", 10)
    if "vuln_nuclei_concurrency"      in data: VULN_NUCLEI_CONCURRENCY      = _i("vuln_nuclei_concurrency", 25)
    if "vuln_nuclei_bulk_size"        in data: VULN_NUCLEI_BULK_SIZE        = _i("vuln_nuclei_bulk_size", 25)
    if "vuln_nuclei_retries"          in data: VULN_NUCLEI_RETRIES          = _i("vuln_nuclei_retries", 1)
    if "vuln_nuclei_max_host_errors"  in data: VULN_NUCLEI_MAX_HOST_ERRORS  = _i("vuln_nuclei_max_host_errors", 30)
    if "vuln_nuclei_interactsh"       in data: VULN_NUCLEI_INTERACTSH       = _b("vuln_nuclei_interactsh")
    if "vuln_nuclei_headless"         in data: VULN_NUCLEI_HEADLESS         = _b("vuln_nuclei_headless")
    if "vuln_nuclei_custom_templates" in data: VULN_NUCLEI_CUSTOM_TEMPLATES = data["vuln_nuclei_custom_templates"] or ""

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


def ha_post(path: str, body: dict, timeout: int = 15):
    """POST to the HA REST API."""
    url = f"{HA_URL}/api/{path}"
    resp = requests.post(url, headers=ha_headers(), json=body, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _ha_discover_sensors() -> list[dict]:
    """Discover numeric HA sensor entities that have long-term statistics."""
    try:
        states = ha_get("states", timeout=15)
    except Exception as e:
        log.warning("HA sensor discovery failed: %s", e)
        return []
    sensors = []
    for s in states:
        eid = s.get("entity_id", "")
        if not eid.startswith("sensor."):
            continue
        state_val = s.get("state", "")
        try:
            float(state_val)
        except (ValueError, TypeError):
            continue
        attrs = s.get("attributes", {})
        if attrs.get("state_class") not in ("measurement", "total_increasing", "total"):
            continue
        sensors.append({
            "entity_id":    eid,
            "name":         attrs.get("friendly_name") or eid,
            "state":        state_val,
            "unit":         attrs.get("unit_of_measurement") or "",
            "device_class": attrs.get("device_class") or "",
            "last_changed": s.get("last_changed", ""),
        })
    return sorted(sensors, key=lambda x: x["name"].lower())


def _ha_sensor_history(entity_ids: list[str], hours: int = 24) -> dict[str, list]:
    """
    Fetch hourly bucketed sensor data for the last `hours` hours.
    Returns {entity_id: [{"mean": v, "min": v, "max": v} | None, ...]} (one entry per hour).
    Uses statistics_during_period first; falls back to history/period for gaps.
    """
    if not entity_ids:
        return {}

    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    start_iso = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    result: dict[str, list] = {}
    missing = list(entity_ids)

    # ── Statistics API (pre-bucketed into hourly bins) ────────────────────────
    try:
        stats = ha_post("statistics_during_period", {
            "start_time":    start_iso,
            "statistic_ids": entity_ids,
            "period":        "hour",
            "types":         ["mean", "min", "max"],
        }, timeout=20)
        if isinstance(stats, dict):
            for eid, records in stats.items():
                if not records:
                    continue
                buckets: list = [None] * hours
                for rec in records:
                    try:
                        rec_start = datetime.fromisoformat(
                            rec["start"].replace("Z", "+00:00")
                        )
                        age_h = (now - rec_start).total_seconds() / 3600
                        idx = hours - 1 - int(age_h)
                        if 0 <= idx < hours:
                            buckets[idx] = {
                                "mean": rec.get("mean"),
                                "min":  rec.get("min"),
                                "max":  rec.get("max"),
                            }
                    except Exception:
                        pass
                result[eid] = buckets
                if eid in missing:
                    missing.remove(eid)
    except Exception as e:
        log.debug("HA statistics_during_period failed: %s", e)

    # ── History API fallback ───────────────────────────────────────────────────
    if missing:
        try:
            path = (
                f"history/period/{start_iso}"
                f"?filter_entity_id={','.join(missing)}"
                "&minimal_response=true&no_attributes=true"
            )
            history = ha_get(path, timeout=20)
            if isinstance(history, list):
                for entity_history in history:
                    if not entity_history:
                        continue
                    eid = entity_history[0].get("entity_id", "")
                    if not eid:
                        continue
                    samples: list[tuple[float, float]] = []
                    for item in entity_history:
                        try:
                            ts_raw = item.get("last_changed") or item.get("lu", "")
                            if isinstance(ts_raw, (int, float)):
                                ts = float(ts_raw)
                            elif ts_raw:
                                ts = datetime.fromisoformat(
                                    ts_raw.replace("Z", "+00:00")
                                ).timestamp()
                            else:
                                continue
                            samples.append((ts, float(item.get("state", ""))))
                        except (ValueError, TypeError):
                            pass
                    buckets = []
                    for i in range(hours):
                        t_end   = now.timestamp() - (hours - 1 - i) * 3600
                        t_start = t_end - 3600
                        vals = [v for t, v in samples if t_start <= t < t_end]
                        if vals:
                            buckets.append({"mean": round(sum(vals)/len(vals), 3),
                                            "min":  round(min(vals), 3),
                                            "max":  round(max(vals), 3)})
                        else:
                            buckets.append(None)
                    result[eid] = buckets
        except Exception as e:
            log.debug("HA history/period fallback failed: %s", e)

    return result


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
    with _mac_port_lock:
        port_snap = dict(_mac_to_port)
    result = []
    for d in devs:
        dev = dict(d)
        if dev.get("monitored"):
            dev["uptime"] = _uptime_stats(d["ip"])
        mac = (dev.get("mac") or "").lower()
        if mac and mac in port_snap:
            dev["switch_port"] = port_snap[mac]
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
    mac = (dev.get("mac") or "").lower()
    if mac:
        with _mac_port_lock:
            port_info = _mac_to_port.get(mac)
        if port_info:
            dev["switch_port"] = port_info
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


@app.route("/api/nmap/all", methods=["POST"])
def api_nmap_all_start():
    global _nmap_all_status
    with _nmap_all_lock:
        if _nmap_all_status.get("state") == "running":
            return jsonify({"status": "already_running", **_nmap_all_status})
    with _devices_lock:
        ips = list(_devices.keys())
    if not ips:
        return jsonify({"status": "no_devices"})
    with _nmap_all_lock:
        _nmap_all_status = {"state": "running", "done": 0, "total": len(ips), "errors": 0}
    threading.Thread(target=_run_nmap_all, args=(ips,), daemon=True, name="nmap-all").start()
    return jsonify({"status": "started", "total": len(ips)})


@app.route("/api/nmap/all", methods=["GET"])
def api_nmap_all_get():
    return jsonify(_nmap_all_status)


@app.route("/api/devices/<ip>/snmp/interfaces", methods=["POST"])
def api_snmp_if_start(ip):
    with _devices_lock:
        if ip not in _devices:
            return jsonify({"error": "not found"}), 404
    if ip in _SNMP_IF_RUNNING:
        return jsonify({"status": "running"})
    community = (request.json or {}).get("community") or SNMP_COMMUNITY
    threading.Thread(target=_run_snmp_if_diag, args=(ip, community),
                     daemon=True, name=f"snmp-if-{ip}").start()
    return jsonify({"status": "started"})


@app.route("/api/devices/<ip>/snmp/interfaces", methods=["GET"])
def api_snmp_if_get(ip):
    if ip in _SNMP_IF_RUNNING:
        return jsonify({"status": "running"})
    res = _SNMP_IF_RESULTS.get(ip)
    return jsonify(res if res else {"status": "none"})


# ── Vulnerability scanning routes ─────────────────────────────────────────────
@app.route("/vulnerabilities")
def vulnerabilities_page():
    return render_template("vulnerabilities.html")


@app.route("/vulnerabilities/config")
def vuln_config_page():
    return render_template("vuln_config.html")


@app.route("/api/vulnerabilities/config", methods=["GET"])
def api_vuln_config_get():
    keys = [k for k in _CONFIG_FIELDS if k.startswith("vuln_")]
    return jsonify({k: _runtime_config.get(k, _CONFIG_FIELDS[k]["default"]) for k in keys})


@app.route("/api/vulnerabilities/config", methods=["POST"])
def api_vuln_config_post():
    data = request.json or {}
    allowed = {k for k in _CONFIG_FIELDS if k.startswith("vuln_")}
    filtered = {k: v for k, v in data.items() if k in allowed}
    _runtime_config.update(filtered)
    _save_config(_runtime_config)
    _apply_config(filtered)
    return jsonify({"status": "ok"})


@app.route("/api/vulnerabilities")
def api_vuln_list():
    with _devices_lock:
        devs = list(_devices.values())
    with _vuln_lock:
        scanning_snap = set(_vuln_scanning)

    hosts = []
    for d in devs:
        ip      = d.get("ip", "")
        vuln    = _vuln_results.get(ip, {})
        findings = vuln.get("findings", [])
        counts  = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        hosts.append({
            "ip":         ip,
            "label":      d.get("name") or d.get("hostname") or d.get("dhcp_hostname") or ip,
            "status":     d.get("status", "unknown"),
            "scanning":   ip in scanning_snap,
            "vuln_status": vuln.get("status"),
            "ts":          vuln.get("ts"),
            "counts":      counts,
            "findings":    findings,
        })
    return jsonify({"hosts": hosts})


@app.route("/api/vulnerabilities/<ip>/scan", methods=["POST"])
def api_vuln_scan_start(ip):
    with _devices_lock:
        if ip not in _devices:
            return jsonify({"error": "not found"}), 404
    with _vuln_lock:
        if ip in _vuln_scanning:
            return jsonify({"status": "already_running"})
    threading.Thread(target=_run_vuln_scan, args=(ip,), daemon=True,
                     name=f"vuln-{ip}").start()
    return jsonify({"status": "started"})


@app.route("/api/vulnerabilities/<ip>", methods=["GET"])
def api_vuln_get(ip):
    with _vuln_lock:
        scanning = ip in _vuln_scanning
    res = _vuln_results.get(ip, {"status": "none", "findings": []})
    return jsonify({**res, "scanning": scanning})


@app.route("/api/vulnerabilities/scan/all", methods=["POST"])
def api_vuln_scan_all():
    with _devices_lock:
        ips = list(_devices.keys())
    started = 0
    for ip in ips:
        with _vuln_lock:
            already = ip in _vuln_scanning
        if not already:
            threading.Thread(target=_run_vuln_scan, args=(ip,), daemon=True,
                             name=f"vuln-{ip}").start()
            started += 1
    return jsonify({"status": "started", "count": started})


@app.route("/api/vulnerabilities/log")
def api_vuln_log():
    since = int(request.args.get("since", 0))
    with _vuln_log_lock:
        entries = [e for e in _vuln_log if e["seq"] > since]
        scanning = bool(_vuln_scanning)
    return jsonify({"entries": entries, "scanning": scanning,
                    "max_seq": _vuln_log_seq})


@app.route("/api/devices/<ip>/nmap", methods=["POST"])
def api_nmap_start(ip):
    with _devices_lock:
        if ip not in _devices:
            return jsonify({"error": "not found"}), 404
    if ip in _nmap_scanning:
        return jsonify({"status": "running"})
    threading.Thread(target=_run_nmap_full, args=(ip,), daemon=True, name=f"nmap-{ip}").start()
    return jsonify({"status": "started"})


@app.route("/api/devices/<ip>/nmap", methods=["GET"])
def api_nmap_result(ip):
    if ip in _nmap_scanning:
        return jsonify({"status": "running"})
    res = _nmap_scan_results.get(ip)
    return jsonify(res if res else {"status": "none"})


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


@app.route("/api/snmp/port/action", methods=["POST"])
def api_snmp_port_action():
    """Bounce, disable, or enable a switch port via SNMP SET on ifAdminStatus."""
    data      = request.json or {}
    switch_ip = (data.get("switch_ip") or "").strip()
    if_idx    = data.get("if_idx")
    action    = (data.get("action") or "").lower()  # bounce | disable | enable

    if not switch_ip or not if_idx or action not in ("bounce", "disable", "enable"):
        return jsonify({"ok": False, "error": "switch_ip, if_idx, and action (bounce|disable|enable) are required"}), 400

    community = _snmp_community_for(switch_ip)
    snmp_port = _snmp_port_for(switch_ip)
    oid       = f"{IF_ADMIN_STATUS_OID}.{if_idx}"

    if action == "bounce":
        threading.Thread(
            target=_do_bounce, args=(switch_ip, if_idx, community, snmp_port),
            daemon=True, name=f"port-bounce-{switch_ip}-{if_idx}"
        ).start()
        return jsonify({"ok": True, "message": f"Bouncing {switch_ip} if{if_idx}…"})

    value = "2" if action == "disable" else "1"
    ok    = _snmpset(switch_ip, community, oid, "i", value, port=snmp_port)
    label = "disabled" if action == "disable" else "enabled"
    return jsonify({"ok": ok, "message": f"Port {label}" if ok else "SNMP SET failed — community may be read-only"})


@app.route("/api/bridge/rescan", methods=["POST"])
def api_bridge_rescan():
    """Trigger an immediate IF-MIB + bridge scan for all configured SNMP switches/APs."""
    if not SNMP_SWITCHES:
        return jsonify({"ok": False, "message": "No SNMP bridge sources configured"}), 400
    threading.Thread(target=_bridge_scan_all, daemon=True, name="bridge-rescan").start()
    n = len(SNMP_SWITCHES)
    return jsonify({"ok": True, "message": f"Rescanning {n} source{'s' if n != 1 else ''}…"})


@app.route("/ipam")
def ipam_page():
    return render_template("ipam.html")


@app.route("/api/ipam")
def api_ipam():
    import ipaddress as _ip
    with _meraki_ipam_lock:
        cache = dict(_meraki_ipam_cache)
    with _devices_lock:
        devs = list(_devices.values())
    with _mac_port_lock:
        mac_snap = dict(_mac_to_port)

    subnets  = cache.get("subnets", [])
    fixed    = cache.get("fixed", {})   # ip → {mac, name, vlan_id, vlan_name}
    ipam_ts  = cache.get("ts", 0)

    # Build a quick lookup: IP → subnet dict
    _subnet_cache: dict = {}
    _parsed_nets: list = []
    for s in subnets:
        try:
            _parsed_nets.append((_ip.ip_network(s["subnet"], strict=False), s))
        except Exception:
            pass

    def _ip_subnet(ip_str: str) -> dict:
        if ip_str in _subnet_cache:
            return _subnet_cache[ip_str]
        try:
            addr = _ip.ip_address(ip_str)
            for net, s in _parsed_nets:
                if addr in net:
                    _subnet_cache[ip_str] = s
                    return s
        except Exception:
            pass
        _subnet_cache[ip_str] = {}
        return {}

    # Infrastructure IPs (Meraki devices: MX, MR, MS)
    infra_ips: set = {minfo["ip"] for minfo in _meraki_net_macs.values() if minfo.get("ip")}

    seen_ips: set = set()
    ip_records: list = []

    for d in devs:
        ip = d.get("ip", "")
        if not ip:
            continue
        seen_ips.add(ip)
        vlan_info = _ip_subnet(ip)
        is_fixed  = ip in fixed
        is_gw     = bool(vlan_info) and ip == vlan_info.get("gateway")
        is_infra  = ip in infra_ips

        if is_gw:
            ip_type = "gateway"
        elif is_fixed:
            ip_type = "reserved"
        elif is_infra:
            ip_type = "infrastructure"
        else:
            ip_type = "dhcp"

        ms = d.get("meraki_status") or ""
        ps = d.get("status") or ""
        if ms == "online" or ps == "up":
            eff_status = "online"
        elif ms == "offline" or ps == "down":
            eff_status = "offline"
        else:
            eff_status = "unknown"

        # Determine connection type and label
        mac_lower    = (d.get("mac") or "").lower().strip()
        port_info    = mac_snap.get(mac_lower, {})
        aruba_conn   = d.get("aruba_connection") or ""
        meraki_conn  = d.get("meraki_connection") or ""
        meraki_wired = d.get("meraki_wired")        # None if not a Meraki client

        if aruba_conn:
            # Aruba Central wireless client
            conn_label  = aruba_conn
            conn_ssid   = d.get("aruba_ssid") or ""
            conn_wired  = False
            conn_port   = ""
        elif meraki_conn and meraki_wired is False:
            # Meraki wireless client
            conn_label  = meraki_conn
            conn_ssid   = d.get("meraki_ssid") or ""
            conn_wired  = False
            conn_port   = ""
        elif meraki_conn and meraki_wired:
            # Meraki wired client (connected to a switch or MX)
            conn_label  = meraki_conn
            conn_ssid   = ""
            conn_wired  = True
            conn_port   = d.get("meraki_port") or ""
        elif port_info.get("switch_name"):
            # SNMP bridge-scan detected switch/AP
            conn_label  = port_info.get("switch_name") or ""
            conn_ssid   = ""
            conn_wired  = not port_info.get("is_wireless", False)
            conn_port   = port_info.get("if_name") or ""
        else:
            conn_label  = ""
            conn_ssid   = ""
            conn_wired  = True
            conn_port   = ""

        fixed_info = fixed.get(ip, {})
        ip_records.append({
            "ip":           ip,
            "hostname":     d.get("dhcp_hostname") or d.get("hostname") or "",
            "name":         d.get("name") or "",
            "mac":          d.get("mac") or "",
            "vendor":       d.get("vendor") or "",
            "status":       eff_status,
            "type":         ip_type,
            "vlan":         vlan_info.get("name", ""),
            "vlan_id":      vlan_info.get("id"),
            "source":       d.get("learned_from") or "",
            "last_seen":    d.get("last_seen"),
            "ping_ms":      d.get("ping_latency_ms"),
            "ssid":         conn_ssid,
            "connection":   conn_label,
            "port":         conn_port,
            "wired":        conn_wired,
            "description":  fixed_info.get("name", ""),
        })

    # Add fixed reservations not yet seen in _devices
    for ip, info in fixed.items():
        if ip in seen_ips:
            continue
        vlan_info = _ip_subnet(ip)
        ip_records.append({
            "ip":           ip,
            "hostname":     info.get("name", ""),
            "name":         info.get("name", ""),
            "mac":          info.get("mac", ""),
            "vendor":       _mac_vendor(info.get("mac", "")),
            "status":       "unknown",
            "type":         "reserved",
            "vlan":         info.get("vlan_name", ""),
            "vlan_id":      info.get("vlan_id"),
            "source":       "Meraki DHCP reservation",
            "last_seen":    None,
            "ping_ms":      None,
            "ssid":         "",
            "connection":   "",
            "wired":        True,
            "description":  info.get("name", ""),
        })

    def _sort_key(r):
        try:
            return tuple(int(x) for x in r["ip"].split("."))
        except Exception:
            return (999, 999, 999, 999)
    ip_records.sort(key=_sort_key)

    # Subnet utilization stats
    subnet_stats: list = []
    for s in subnets:
        try:
            net          = _ip.ip_network(s["subnet"], strict=False)
            total_usable = max(0, net.num_addresses - 2)
            ips_here     = [r for r in ip_records
                            if r.get("vlan_id") == s["id"] or _ip_subnet(r["ip"]).get("id") == s["id"]]
            n_online   = sum(1 for r in ips_here if r["status"] == "online")
            n_offline  = sum(1 for r in ips_here if r["status"] == "offline")
            n_unknown  = sum(1 for r in ips_here if r["status"] == "unknown")
            n_reserved = sum(1 for r in ips_here if r["type"] == "reserved")
            n_gateway  = sum(1 for r in ips_here if r["type"] == "gateway")
            n_infra    = sum(1 for r in ips_here if r["type"] == "infrastructure")
            n_known    = len(ips_here)
            excluded   = 0
            for rr in s.get("reserved_ranges", []):
                try:
                    excluded += int(_ip.ip_address(rr["end"])) - int(_ip.ip_address(rr["start"])) + 1
                except Exception:
                    pass
            available = max(0, total_usable - n_known - excluded)
            util_pct  = round(n_known / total_usable * 100, 1) if total_usable > 0 else 0
            subnet_stats.append({
                **s,
                "total":         total_usable,
                "known":         n_known,
                "online":        n_online,
                "offline":       n_offline,
                "unknown_count": n_unknown,
                "reserved":      n_reserved,
                "gateway_count": n_gateway,
                "infra":         n_infra,
                "excluded":      excluded,
                "available":     available,
                "util_pct":      util_pct,
            })
        except Exception as e:
            log.debug("IPAM subnet stat error %s: %s", s.get("subnet"), e)

    return jsonify({"ts": ipam_ts, "subnets": subnet_stats, "ips": ip_records})


@app.route("/api/ipam/refresh", methods=["POST"])
def api_ipam_refresh():
    if not MERAKI_API_KEY or not MERAKI_NETWORK_ID:
        return jsonify({"ok": False, "error": "Meraki API key and network ID required"}), 400
    threading.Thread(target=_poll_meraki_ipam, daemon=True, name="ipam-refresh").start()
    return jsonify({"ok": True, "message": "IPAM refresh started"})


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


@app.route("/api/aruba_central/poll", methods=["POST"])
def api_aruba_central_poll():
    if not ARUBA_CENTRAL_API_URL or not ARUBA_CENTRAL_API_TOKEN:
        return jsonify({"ok": False, "error": "Aruba Central API not configured"}), 400
    threading.Thread(target=_poll_aruba_central_clients, daemon=True).start()
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
                threading.Thread(target=poll_once, daemon=True).start()


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


@app.route("/switchmap")
def switchmap_page():
    return render_template("switchmap.html")


@app.route("/api/switchmap")
def api_switchmap():
    with _devices_lock:
        devs = list(_devices.values())
    with _mac_port_lock:
        mac_snap = dict(_mac_to_port)

    mac_to_dev: dict = {}
    for d in devs:
        mac = (d.get("mac") or "").lower().strip()
        if mac:
            mac_to_dev[mac] = d

    groups: dict = {}

    def _get_or_create(gid: str, name: str, gtype: str, ip: str) -> dict:
        if gid not in groups:
            groups[gid] = {"id": gid, "name": name, "type": gtype, "ip": ip, "clients": []}
        return groups[gid]

    # Only genuinely wireless clients displace their SNMP bridge entry.
    # Meraki wired clients (meraki_wired=True) connect through an MX gateway → they belong
    # on their switch port, not under the gateway as if it were an AP.
    # Aruba Central only reports wireless clients, so all aruba_connection values are APs.
    wireless_macs: set = set()
    for d in devs:
        mac = (d.get("mac") or "").lower().strip()
        if not mac:
            continue
        meraki_conn = d.get("meraki_connection") or ""
        aruba_conn  = d.get("aruba_connection") or ""
        is_meraki_wireless = meraki_conn and not d.get("meraki_wired", False)
        if is_meraki_wireless or aruba_conn:
            wireless_macs.add(mac)

    for mac, port_info in mac_snap.items():
        if mac in wireless_macs:
            continue  # handled by meraki/aruba section below
        if mac in _infra_macs:
            continue  # AP/switch's own interface MAC (BSSID, management NIC, etc.)
        sw_ip   = port_info.get("switch_ip", "")
        sw_name = port_info.get("switch_name") or sw_ip
        is_wl   = bool(port_info.get("is_wireless"))
        gtype   = "ap" if is_wl else "switch"
        grp     = _get_or_create(f"snmp:{sw_ip}", sw_name, gtype, sw_ip)
        dev     = mac_to_dev.get(mac)
        grp["clients"].append({
            "mac":            mac,
            "ip":             dev["ip"]                                       if dev else "",
            "name":           dev.get("name") or dev.get("hostname") or ""   if dev else "",
            "vendor":         dev.get("vendor") or ""                         if dev else "",
            "status":         dev.get("status") or ""                         if dev else "",
            "port":           port_info.get("if_name") or "",
            "port_alias":     port_info.get("if_alias") or "",
            "is_wireless":    is_wl,
            "port_mac_count": port_info.get("port_mac_count", 1),
            "rssi":           port_info.get("rssi_est"),
            "rssi_est":       port_info.get("rssi_est") is not None,
            "snr":            port_info.get("snr"),
            "speed":          port_info.get("speed"),
            "wifi_cap":       None,
            "if_idx":         port_info.get("if_idx"),
            "switch_ip":      sw_ip,
        })

    for d in devs:
        mac         = (d.get("mac") or "").lower().strip()
        meraki_conn = d.get("meraki_connection") or ""
        aruba_conn  = d.get("aruba_connection") or ""
        if meraki_conn and not d.get("meraki_wired", False):
            grp = _get_or_create(f"meraki:{meraki_conn}", meraki_conn, "ap", "")
            sig = {"rssi": d.get("meraki_rssi"), "snr": d.get("meraki_snr"),
                   "speed": d.get("meraki_speed"),
                   "wifi_cap": _fmt_wifi_cap(d.get("meraki_wifi_cap") or "")}
        elif aruba_conn:
            grp = _get_or_create(f"aruba:{aruba_conn}", aruba_conn, "ap", "")
            msnap = mac_snap.get(mac, {})
            sig = {"rssi": None, "snr": msnap.get("snr"), "speed": msnap.get("speed"), "wifi_cap": None}
        else:
            continue
        grp["clients"].append({
            "mac":            mac,
            "ip":             d["ip"],
            "name":           d.get("name") or d.get("hostname") or "",
            "vendor":         d.get("vendor") or "",
            "status":         d.get("status") or "",
            "port":           "wifi",
            "port_alias":     "",
            "is_wireless":    True,
            "port_mac_count": 1,
            **sig,
        })

    for grp in groups.values():
        grp["clients"].sort(key=lambda c: (c["port"], c["ip"]))

    result = sorted(groups.values(), key=lambda g: (g["type"] != "switch", g["name"].lower()))
    return jsonify(result)


@app.route("/topology")
def topology_page():
    return render_template("topology.html")


_WIRELESS_KEYWORDS = ("ath", "wlan", "wifi", "bss", "vap", "wl")


def _snmp_node_type(switch_ip: str) -> str:
    """Return 'ap' if any port recorded for switch_ip has a wireless interface name."""
    with _mac_port_lock:
        for info in _mac_to_port.values():
            if info["switch_ip"] == switch_ip:
                if any(kw in (info.get("if_name") or "").lower() for kw in _WIRELESS_KEYWORDS):
                    return "ap"
    return "switch"


@app.route("/api/topology")
def api_topology():
    with _devices_lock:
        devs     = list(_devices.values())
        dev_by_ip = {d["ip"]: d for d in devs if "ip" in d}

    with _mac_port_lock:
        mac_port_snap = dict(_mac_to_port)

    topo     = _meraki_topology          # snapshot (dict, may be empty)
    net_macs = dict(_meraki_net_macs)    # mac → {name, model, type, ip}
    net_devs = dict(_meraki_net_devs)    # name → type

    nodes: list = []
    edges: list = []
    node_ids: set = set()

    def _add_node(n: dict) -> None:
        if n["id"] not in node_ids:
            node_ids.add(n["id"])
            nodes.append(n)

    # ── Build infrastructure layer from Meraki link-layer topology ────────────
    infra_mac_to_id: dict = {}   # mac → node id used in edges

    if topo.get("nodes"):
        for tn in topo["nodes"]:
            mac_lc = (tn.get("mac") or "").lower()
            info   = net_macs.get(mac_lc, {})
            name   = info.get("name") or tn.get("meraki", {}).get("device", {}).get("name") or mac_lc
            model  = info.get("model") or tn.get("meraki", {}).get("device", {}).get("model") or ""
            ntype  = _meraki_dev_type(model) if model else "switch"
            ip     = info.get("ip") or ""
            nid    = ip or f"meraki:{name}"
            infra_mac_to_id[mac_lc] = nid
            _add_node({"id": nid, "label": name, "type": ntype,
                       "status": "online", "ip": ip, "vendor": model, "mac": mac_lc,
                       "infra": True})

        for lnk in (topo.get("links") or []):
            ends = lnk.get("ends") or []
            if len(ends) < 2:
                continue
            id_a = infra_mac_to_id.get((ends[0].get("node") or {}).get("mac", "").lower())
            id_b = infra_mac_to_id.get((ends[1].get("node") or {}).get("mac", "").lower())
            if id_a and id_b and id_a != id_b:
                edges.append({"from": id_a, "to": id_b, "infra": True})

    # ── Fallback: infer gateway from IP heuristic if no topology ────────────
    gateway_node_id: str = ""
    gw_candidates = [n for n in nodes if n.get("type") == "gateway"]
    if gw_candidates:
        gateway_node_id = gw_candidates[0]["id"]
    else:
        for d in devs:
            ip = d.get("ip", "")
            if ip.endswith(".1") or ip.endswith(".254"):
                gateway_node_id = ip
                _add_node({"id": ip,
                           "label": d.get("name") or ip,
                           "type": "gateway", "status": d.get("status", "unknown"),
                           "ip": ip, "vendor": d.get("vendor", ""), "mac": d.get("mac", "")})
                break

    # ── Client/device layer ───────────────────────────────────────────────────
    snmp_intermediate_ips = set(info["switch_ip"] for info in mac_port_snap.values())

    for d in devs:
        ip     = d.get("ip", "")
        mac_lc = (d.get("mac") or "").lower()
        label  = d.get("name") or d.get("hostname") or d.get("dhcp_hostname") or ip

        # Skip if already added as an infrastructure node
        if ip and ip in node_ids:
            continue
        if mac_lc and mac_lc in infra_mac_to_id:
            continue

        is_infra_snmp = ip in snmp_intermediate_ips
        ntype = "device"
        if is_infra_snmp:
            ntype = _snmp_node_type(ip)

        _add_node({"id": ip, "label": label, "type": ntype,
                   "status": d.get("status", "unknown"),
                   "ip": ip, "vendor": d.get("vendor", ""), "mac": mac_lc})

        # Connect to Meraki AP/switch by association name
        conn_name = d.get("meraki_connection") or ""
        if conn_name:
            parent_info = next((v for v in net_macs.values() if v.get("name") == conn_name), None)
            parent_ip   = parent_info.get("ip", "") if parent_info else ""
            parent_id   = parent_ip or f"meraki:{conn_name}"
            if parent_id not in node_ids:
                # AP not in link-layer topo → add standalone
                ptype = net_devs.get(conn_name, "ap")
                _add_node({"id": parent_id, "label": conn_name, "type": ptype,
                           "status": "online", "ip": parent_ip, "vendor": "", "mac": ""})
                if gateway_node_id and gateway_node_id != parent_id:
                    edges.append({"from": parent_id, "to": gateway_node_id})
            edges.append({"from": ip, "to": parent_id})
            continue

        # Connect via SNMP bridge data (Aruba / managed switch)
        port_info = mac_port_snap.get(mac_lc)
        if port_info:
            sw_ip = port_info["switch_ip"]
            if sw_ip not in node_ids:
                sw_dev = dev_by_ip.get(sw_ip, {})
                sw_label = sw_dev.get("name") or sw_dev.get("hostname") or port_info.get("switch_name") or sw_ip
                _add_node({"id": sw_ip, "label": sw_label,
                           "type": _snmp_node_type(sw_ip),
                           "status": "online", "ip": sw_ip, "vendor": "", "mac": ""})
                if gateway_node_id and gateway_node_id != sw_ip:
                    edges.append({"from": sw_ip, "to": gateway_node_id})
            edges.append({"from": ip, "to": sw_ip})

    return jsonify({"nodes": nodes, "edges": edges,
                    "meraki_topo": bool(topo.get("nodes"))})


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

    # Load persisted bridge MIB data so switch ports are visible before first scan
    _load_mac_to_port()

    # Load persisted vuln scan results so findings survive restarts
    _vuln_results.update(_load_vuln_results())

    # Start background pollers
    threading.Thread(target=_ha_poller_loop,          daemon=True, name="ha-poller").start()
    threading.Thread(target=_device_ping_loop,        daemon=True, name="device-ping").start()
    threading.Thread(target=_snmp_poller_loop,        daemon=True, name="snmp-poller").start()
    threading.Thread(target=_meraki_api_poller_loop,  daemon=True, name="meraki-api-poller").start()
    threading.Thread(target=_aruba_central_poller_loop, daemon=True, name="aruba-central-poller").start()
    threading.Thread(target=_peer_health_loop,        daemon=True, name="peer-health").start()
    threading.Thread(target=_primary_peer_check_loop, daemon=True, name="peer-check").start()
    threading.Thread(target=_feature_probe_loop,      daemon=True, name="feature-probe").start()
    threading.Thread(target=_mdns_listen_loop,        daemon=True, name="mdns-listener").start()
    threading.Thread(target=_vuln_auto_scan_loop,     daemon=True, name="vuln-auto").start()
    threading.Thread(target=_snmp_bridge_scan_loop,   daemon=True, name="bridge-scan").start()
    threading.Thread(target=_nuclei_update_templates, daemon=True, name="nuclei-update").start()

    # Give the first poll a moment
    time.sleep(2)

    port = int(os.environ.get("PORT", "9099"))
    log.info("Starting Farol on port %d", port)
    app.run(host="0.0.0.0", port=port)
