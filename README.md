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
| `WOL_DEFAULT_BROADCAST` | Default Wake-on-LAN broadcast address, defaults to `255.255.255.255` |
| `WOL_DEFAULT_PORT` | Default Wake-on-LAN UDP port, defaults to `9` |
| `WOL_EXTRA_BROADCASTS` | Optional extra comma-separated broadcast targets, for example `10.13.37.255` |
| `WOL_REPEAT_COUNT` | Number of UDP wake sends per target, defaults to `3` |
| `WOL_BIND_ADDRESS` / `WOL_BIND_PORT` | Optional local UDP bind settings for wake packets |
| `WOL_DEVICES` | Optional JSON seed for first-run wake machines |
| `HOME_ASSISTANT_URL` / `HOME_ASSISTANT_TOKEN` | Home Assistant REST API access |
| `UNIFI_URL` / `UNIFI_USERNAME` / `UNIFI_PASSWORD` | UniFi Network local controller access |
| `UNIFI_API_KEY` | Optional API key header for controller setups that support it |
| `UNIFI_SITE` | UniFi site name, usually `default`; admins can pick discovered sites in the UI |
| `UNIFI_HOST_ID` / `UNIFI_SITE_ID` | Optional Site Manager identifiers for distinguishing several consoles that all have a `default` Network site |
| `UNIFI_SITE_MANAGER_URL` | Optional Site Manager API base override; defaults to `https://api.ui.com` |
| `UNIFI_LOGIN_PATHS` | Login paths to try, defaults to UniFi OS then classic controller |
| `UNIFI_API_PREFIXES` | API path prefixes to try, defaults to `/proxy/network` then classic root |
| `STATUS_SITES` | JSON array used to seed the Sites page |

Home Assistant uses its REST API for states, logbook, events, services, system health, and error log. UniFi uses the local Network application API style because it exposes the broadest status and log surface for a NAS-local dashboard; with a Site Manager API key, the UniFi page also asks the documented Site Manager `/v1/hosts` and `/v1/sites` endpoints so admins can choose between consoles even when every Network site is named `default`. Connected clients are collected from the official Network Integration `/v1/sites/{siteId}/clients` endpoint using the UUID returned by Network Integration `/v1/sites`; legacy endpoints such as `api/s/default/stat/sta` use the site's `internalReference` instead. If UniFi returns summary counts through Site Manager but does not return detailed client rows, ChempBoard shows the Site Manager client count clearly as summary-only data.

Admins can change NAS disk paths/log files, Home Assistant URL/token, UniFi URL/credentials/API key, and WOL defaults from the Settings page. Saved settings live in `DATA_DIR/settings.json` and override environment defaults without rebuilding the container.

## Wake-on-LAN

Admins can add wake machines from the Wake page. Every signed-in user with ChempBoard access can send wake packets for enabled machines.

Each machine stores:

| Field | Example |
| --- | --- |
| `name` | `Studio PC` |
| `mac` | `AA:BB:CC:DD:EE:FF` |
| `broadcast` | `10.13.37.33` or `10.13.37.255` |
| `port` | `9` |
| `tags` | `["studio"]` |
| `enabled` | `true` |

For GPTWOL-style setups, enter the machine IP, for example `10.13.37.33`. ChempBoard sends a true unicast packet to that IP, a legacy broadcast-flag packet to the same IP, an inferred `/24` directed broadcast such as `10.13.37.255`, and the configured default broadcast such as `255.255.255.255`. It records every UDP send attempt and runs a short TCP check on the configured port so the Wake page can show whether the machine looks awake.

If broadcast packets do not cross Docker networking on your NAS, use a directed subnet broadcast such as `10.13.37.255` or the host-network compose file below.

If the wake log says the UDP packets were sent but the machine stays asleep:

1. Prefer `10.13.37.255` as the machine broadcast on a `10.13.37.x/24` network.
2. Run ChempBoard with `docker-compose.truenas.host-network.yml` so packets leave from the NAS host network instead of Docker bridge networking.
3. Confirm the target machine is wired Ethernet, not Wi-Fi, and has Wake-on-LAN enabled in BIOS/UEFI and the OS.
4. On Windows, disable Fast Startup and enable "Wake on Magic Packet" for the NIC.
5. If the machine is on another VLAN, configure a directed broadcast or WOL relay on the network side.

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

For Wake-on-LAN troubleshooting, use the host-network variant instead:

```sh
docker compose -f docker-compose.truenas.host-network.yml pull
docker compose -f docker-compose.truenas.host-network.yml up -d
```

With host networking there is no Docker `ports:` mapping. Set `HOST_PORT=5035` if your proxy points at `http://10.13.37.11:5035`, otherwise the default is `8091`.

The default TrueNAS data path is `/mnt/SSD/Apps/ChempBoard`. Adjust it if your apps dataset lives somewhere else. Make sure Auth Manager/Portal has an app permission named `chempboard`, then grant it to the users who should see this dashboard.
