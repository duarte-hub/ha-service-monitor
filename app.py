"""
Home Assistant Service Monitor
Monitors Z-Wave JS UI, Zigbee2MQTT, and SLZB coordinator health.
Provides a live web dashboard and email alerts.
"""

import os
import time
import json
import logging
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta

import socket
import subprocess

import websocket
import requests
from flask import Flask, render_template, jsonify

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

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ha-monitor")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Shared state
monitor_state = {
    "last_poll": None,
    "services": {},
    "coordinators": {},
    "entities": {},
    "ha_reachable": False,
    "ha_version": "",
}
state_lock = threading.Lock()
z2m_update_status: dict = {"state": "idle", "message": "", "log": []}
alert_history: dict[str, float] = {}  # key -> last alert timestamp


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

# Entity IDs to watch
WATCHED_ENTITIES = {
    "Zigbee2MQTT Bridge": "binary_sensor.zigbee2mqtt_bridge_connection_state",
    "Zigbee2MQTT Bridge (Edge)": "binary_sensor.zigbee2mqtt_bridge_connection_state_2",
    "SLZB-MR1 Zigbee Chip Temp": "sensor.slzb_mr1_zigbee_chip_temp",
    "SLZB-MR1 Zigbee Type": "sensor.slzb_mr1_zigbee_type_2",
    "SLZB-MR1U Zigbee Chip Temp": "sensor.slzb_mr1u_zigbee_chip_temp",
    "SLZB-MR1U Zigbee Type": "sensor.slzb_mr1u_zigbee_type",
}

TEMP_WARN_THRESHOLD = float(os.environ.get("TEMP_WARN_THRESHOLD", "60"))

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


def check_entity(entity_id: str) -> dict:
    """Return entity state dict."""
    try:
        data = ha_get(f"states/{entity_id}")
        state = data.get("state", "unknown")
        attrs = data.get("attributes", {})
        friendly = attrs.get("friendly_name", entity_id)

        # Determine OK status
        ok = True
        if state in ("unavailable", "unknown"):
            ok = False
        elif entity_id.startswith("binary_sensor.") and state != "on":
            ok = False

        # Temperature warning
        warn = ""
        if "chip_temp" in entity_id:
            try:
                temp = float(state)
                if temp >= TEMP_WARN_THRESHOLD:
                    ok = False
                    warn = f" ⚠ HIGH TEMP"
            except (ValueError, TypeError):
                pass

        return {
            "state": state,
            "ok": ok,
            "friendly_name": friendly,
            "detail": f"{state}{warn}",
        }
    except Exception as e:
        return {"state": "error", "ok": False, "friendly_name": entity_id, "detail": str(e)}


def poll_once():
    """Run one monitoring cycle."""
    now = datetime.now(timezone.utc).isoformat()
    services = {}
    entities = {}
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
                "entities": {},
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

    # 3. Check entities
    for label, eid in WATCHED_ENTITIES.items():
        result = check_entity(eid)
        entities[label] = result
        if not result["ok"]:
            maybe_alert(f"entity_{eid}", f"{label} issue", result["detail"])
            log.warning("Entity %s: %s", label, result["detail"])

    # 4. Update shared state
    with state_lock:
        monitor_state.update({
            "last_poll": now,
            "ha_reachable": ha_reachable,
            "ha_version": ha_version,
            "services": services,
            "entities": entities,
        })
    log.info("Poll complete — HA reachable, %d add-ons, %d entities checked",
             len(services), len(entities))


# ---------------------------------------------------------------------------
# Alerts — via Home Assistant companion app push notifications
# ---------------------------------------------------------------------------
NOTIFY_SERVICE = os.environ.get("NOTIFY_SERVICE", "notify.mobile_app_iphoned")


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
            "title": f"🏠 {subject}",
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


def maybe_alert(key: str, subject: str, detail: str):
    """Send alert if cooldown has elapsed."""
    now = time.time()
    last = alert_history.get(key, 0)
    if now - last >= ALERT_COOLDOWN:
        alert_history[key] = now
        threading.Thread(target=send_push, args=(subject, detail), daemon=True).start()


# ---------------------------------------------------------------------------
# Background poller
# ---------------------------------------------------------------------------
def poller_loop():
    """Continuously poll HA on a fixed interval."""
    while True:
        try:
            poll_once()
        except Exception as e:
            log.exception("Unhandled error in poller: %s", e)
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


@app.route("/api/update_z2m", methods=["POST"])
def api_update_z2m():
    """Uninstall Z2M Edge, refresh store, reinstall, restore config via HA WebSocket supervisor/api."""
    global z2m_update_status
    Z2M_EDGE_SLUG = os.environ.get("Z2M_EDGE_SLUG", "45df7312_zigbee2mqtt_edge")
    Z2M_EDGE_PORT = int(os.environ.get("Z2M_EDGE_PORT", "8486"))

    def _set(state, message):
        global z2m_update_status
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = f"[{ts}] {message}"
        prev_log = z2m_update_status.get("log", [])
        z2m_update_status = {"state": state, "message": message, "log": prev_log + [entry]}
        log.info("Z2M update [%s]: %s", state, message)

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
            _dbg(f"Backed up options: {json.dumps(saved_options)[:500]}")
            if not saved_options:
                raise RuntimeError(f"Could not read addon options — full info: {info}")
            _dbg(f"Addon state at backup: {info.get('state')}, version: {info.get('version')}")

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

            # Step 4 — install latest; retry a few times in case store cache is still warming
            _set("running", "Installing latest Z2M Edge…")
            for install_attempt in range(3):
                try:
                    install_result = _ws_sup("POST", f"/store/addons/{Z2M_EDGE_SLUG}/install", timeout=300)
                    _dbg(f"Install result: {install_result}")
                    break
                except Exception as ie:
                    _dbg(f"Install attempt {install_attempt + 1} error: {ie}")
                    if install_attempt < 2:
                        _set("running", f"Install attempt {install_attempt + 1} failed — retrying in 15 s…")
                        time.sleep(15)
                    else:
                        raise

            # Step 5 — poll addon state until it settles (up to 6 min, fresh WS each poll)
            _set("running", "Waiting for install to complete…")
            for attempt in range(72):
                time.sleep(5)
                try:
                    chk = _ws_sup("GET", f"/addons/{Z2M_EDGE_SLUG}/info")
                    addon_state = chk.get("state", "")
                    _dbg(f"Poll {attempt + 1}: addon state={addon_state}")
                    if addon_state in ("stopped", "started", "running"):
                        break
                except Exception as e:
                    _dbg(f"Poll {attempt + 1} error: {e}")
                _set("running", f"Waiting for install… ({(attempt + 1) * 5}s)")
            else:
                raise RuntimeError("Timed out waiting for addon to install")

            # Step 6 — restore saved options; set network port binding
            _set("running", "Restoring config options…")
            options_payload: dict = {"options": saved_options}
            if Z2M_EDGE_PORT:
                options_payload["network"] = {"8485/tcp": Z2M_EDGE_PORT}
            _dbg(f"Options payload: {json.dumps(options_payload)[:500]}")
            options_result = _ws_sup("POST", f"/addons/{Z2M_EDGE_SLUG}/options", options_payload)
            _dbg(f"Options result: {options_result}")

            # Step 7 — start
            _set("running", "Starting Z2M Edge…")
            start_result = _ws_sup("POST", f"/addons/{Z2M_EDGE_SLUG}/start")
            _dbg(f"Start result: {start_result}")

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

    # Start background poller
    t = threading.Thread(target=poller_loop, daemon=True)
    t.start()

    # Give the first poll a moment
    time.sleep(2)

    port = int(os.environ.get("PORT", "9099"))
    log.info("Starting HA Service Monitor on port %d", port)
    app.run(host="0.0.0.0", port=port)
