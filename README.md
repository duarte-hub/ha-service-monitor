# ha-service-monitor

A lightweight Docker container that monitors key Home Assistant add-ons — **Z-Wave JS UI**, **Zigbee2MQTT**, and the **SLZB coordinator** — and exposes a live web dashboard with optional email alerts.

## Features

- Polls service health on a configurable interval (default 30 s)
- Live web dashboard on port `9099`
- Email alerts when a service goes down or recovers
- Fully configured via environment variables — no code changes needed

## Quick start

```bash
cp docker-compose.yml docker-compose.override.yml   # optional: keep secrets out of VCS
# edit docker-compose.yml / .env with your values
docker compose up -d
```

Open `http://<host>:9099` in your browser.

## Configuration

All options are set via environment variables:

| Variable | Default | Description |
|---|---|---|
| `HA_URL` | `http://192.168.0.20:8123` | Home Assistant base URL |
| `HA_TOKEN` | _(required)_ | Long-lived HA access token |
| `POLL_INTERVAL` | `30` | Seconds between health checks |

Email and additional service variables are documented in `app.py`.

## Docker

```bash
docker build -t ha-service-monitor .
docker run -e HA_TOKEN=<token> -p 9099:9099 ha-service-monitor
```

## Requirements

- Python 3.12+
- See `requirements.txt` (`flask`, `requests`, `websocket-client`)
