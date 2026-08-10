# ChempBoard

ChempBoard is a small NAS status dashboard protected by Auth Manager. It collects local NAS uptime/load/memory/disk/log data, optional Docker container state, Home Assistant state/logbook/error log data, UniFi Network health/client/device/event data, and configurable site status checks.

## Auth Manager

The Auth Manager app id is `chempboard`. Users need that app permission before they can sign in.

Required environment:

| Variable | Purpose |
| --- | --- |
| `JWT_SECRET` | Same shared secret used by Auth Manager |
| `AUTH_SERVICE_URL` | Server-to-server Auth Manager URL |
| `AUTH_SERVICE_PUBLIC_URL` | Browser-facing Auth Manager URL for password-change redirects |
| `APP_NAME` | Defaults to `chempboard` |

## Data Sources

| Variable | Purpose |
| --- | --- |
| `NAS_PROC_PATH` | Host `/proc` mount, defaults to `/host/proc` in Docker |
| `NAS_DISK_PATHS` | Comma-separated paths to run `df` against |
| `NAS_LOG_FILES` | Optional comma-separated log files; otherwise common Linux/macOS NAS logs are auto-detected |
| `DOCKER_SOCKET` | Optional Docker socket path for container status |
| `HOME_ASSISTANT_URL` / `HOME_ASSISTANT_TOKEN` | Home Assistant REST API access |
| `UNIFI_URL` / `UNIFI_USERNAME` / `UNIFI_PASSWORD` | UniFi Network local controller access |
| `UNIFI_API_KEY` | Optional API key header for controller setups that support it |
| `UNIFI_SITE` | UniFi site name, usually `default` |
| `UNIFI_LOGIN_PATHS` | Login paths to try, defaults to UniFi OS then classic controller |
| `UNIFI_API_PREFIXES` | API path prefixes to try, defaults to `/proxy/network` then classic root |
| `STATUS_SITES` | JSON array used to seed the Sites page |

Home Assistant uses its REST API for states, logbook, events, services, system health, and error log. UniFi uses the local Network application API style because it exposes the broadest status and log surface for a NAS-local dashboard; newer official UniFi API docs are also available inside UniFi Network under Settings > Integrations.

## Local Run

```sh
npm install
AUTH_DISABLED=true PORT=3000 npm start
```

Open `http://localhost:3000`. `AUTH_DISABLED=true` creates a local admin session for setup/testing only.

## Docker

```sh
cp .env.example .env
docker compose up -d --build
```

Set `JWT_SECRET` to the exact same value used by Auth Manager.

## TrueNAS

Use `docker-compose.truenas.yml` as the Custom App compose file after the image has been published by GitHub Actions:

```sh
docker compose -f docker-compose.truenas.yml pull
docker compose -f docker-compose.truenas.yml up -d
```

The default TrueNAS data path is `/mnt/SSD/Apps/ChempBoard`. Adjust it if your apps dataset lives somewhere else. Make sure Auth Manager/Portal has an app permission named `chempboard`, then grant it to the users who should see this dashboard.
