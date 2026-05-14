# Farol

A lightweight Docker container that monitors Home Assistant add-ons and network devices, with a live web dashboard and email/push alerts.

## Features

- Monitors HA add-ons (Z-Wave JS UI, Zigbee2MQTT, Mosquitto) and network devices
- Live web dashboard on port `9099`
- Email and push notification alerts when something goes down or recovers
- Configurable polling intervals per service type
- Fully configured via environment variables or the built-in settings UI

## Quick start

```bash
# edit docker-compose.yml / .env with your values
docker compose up -d
```

Open `http://<host>:9099` in your browser.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `HA_URL` | `http://192.168.0.20:8123` | Home Assistant base URL |
| `HA_TOKEN` | _(required)_ | Long-lived HA access token |
| `POLL_INTERVAL` | `30` | Seconds between device ping checks |
| `HA_POLL_INTERVAL` | `30` | Seconds between HA add-on checks |

All options can also be set in the Settings UI and are persisted to `/data/monitor_config.json`.

## Docker

```bash
docker build -t farol .
docker run -e HA_TOKEN=<token> -p 9099:9099 farol
```

## Requirements

- Python 3.12+
- See `requirements.txt` (`flask`, `requests`, `websocket-client`)
