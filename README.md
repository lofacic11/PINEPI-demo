# PinePi Prototype v1

PinePi is a Raspberry Pi wireless-auditing appliance for controlled, authorized cybersecurity education. Prototype v1 provides a responsive web interface for passive Recon, a controlled test Access Point, raw and WPA/WPA2 handshake capture, session exports, and operational logs.

It is not a password-attack platform. It does not include credential collection, phishing, automated evil-twin behavior, password cracking, brute force, or persistent client disruption. The only external-network deauthentication control is a single, bounded, client-specific reconnect request inside an already-running handshake capture, for networks and devices the operator is authorized to test. Administrative Kick/Block/Unblock controls remain limited to stations on PinePi's own hosted test AP.

## Hardware and network model

`wlan0` is permanently reserved for the open **PinePi** management WLAN. It serves the web UI at `http://10.42.0.1:8080/` and is excluded in both the frontend and backend from Recon, standalone Capture, test-AP, and uplink selection.

At least one additional Linux-supported USB Wi-Fi adapter is required for audit operations. Interfaces are discovered dynamically—there is no `wlan1` role assumption. PinePi queries each radio for monitor and AP modes and shows only eligible, free interfaces. Reservations are per interface, so Recon on one external radio can run alongside a test AP on another. The test AP also reserves its selected uplink for the session.

The management WLAN intentionally remains open for Prototype v1. Use PinePi only in an isolated, supervised environment.

## Features

- Dashboard: live CPU, memory, filesystem, temperature, uptime, real interfaces, active operations, and the latest stored wireless landscape.
- Recon: monitor-capable interface selection, live status, parsed airodump-ng AP/client observations, channel/security charts, searching, sorting, detail/association view, history, CSV, and JSON.
- Access Point: AP-capable adapter selection, Open or WPA2-PSK, readable/copyable live passphrase, verified hostapd state, dnsmasq DHCP, automatic or explicit connected uplink, isolated nftables NAT state, per-client metadata and traffic tracking, Kick/Block/Unblock administration for the owned AP, optional AP-interface traffic capture, history, and ZIP export.
- Capture: Recon-targeted WPA/WPA2 handshake capture or raw channel capture, live three-state handshake analysis, observed-client selection, an optional bounded reconnect request, status/history, PCAP download, safe JSON analysis, and deletion.
- Logs: structured, bounded event history with level/component/search filters and TXT/CSV/JSON exports.
- Mobile UI: hamburger navigation and card-based alternatives for wide tables.
- Storage safety: 250 MB default capture ceiling, minimum-free-space guard before and during capture, bounded application logs, streaming file downloads, and conservative PCAP inspection.

AP ZIPs include only available session artifacts: `metadata.json`, `clients.csv`, `events.log`, and `traffic.pcapng`. WPA2 passphrases are never stored in the database, structured logs, or export metadata; the temporary hostapd configuration is deleted as soon as hostapd and dnsmasq are verified.

### Access Point client accounting and administration

PinePi reads per-station counters from `iw dev <interface> station dump`. Linux reports those counters from the AP's perspective: AP RX is data sent by the client, and AP TX is data sent to the client. PinePi normalizes the domain model, API, UI, and exports to the client perspective:

- `download_bytes` / Download/RX is AP TX, meaning bytes received by the client.
- `upload_bytes` / Upload/TX is AP RX, meaning bytes transmitted by the client.

Totals are maintained independently per MAC and AP session. They accumulate deltas while an association is stable and preserve earlier bytes when a station reconnects and its kernel counters reset. A new AP session starts new totals. Starting or stopping packet capture does not alter station accounting; captures and station counters are independent observations and need not have identical byte totals.

Database schema version 4 migrates legacy AP-side `rx_bytes` into `upload_bytes` and legacy AP-side `tx_bytes` into `download_bytes`, and adds handshake/reconnect metadata to existing capture rows without moving capture files into SQLite. New API responses and exports intentionally use only the explicit traffic names; legacy SQLite columns may remain in an upgraded database but are no longer exported.

For an associated station, PinePi first correlates its MAC with a non-expired lease in that AP session's private dnsmasq lease file. If no valid lease exists, it may use a valid neighbor-table address on the same AP interface and `10.77.0.0/24` subnet. It never synthesizes an address, and a lease or neighbor entry alone is not treated as a connected station. IP and hostname can remain unavailable before DHCP completes, for static-IP clients, after an entry expires, or when neither source has a valid current mapping.

Kick asks hostapd to deauthenticate the currently associated station once; it may reconnect normally. Block adds the station MAC to the runtime deny ACL of the active PinePi hostapd instance and disconnects it; Unblock removes that entry. Blocks last only for the active AP session. These commands are accepted only for the exact external interface, session directory, and live hostapd process owned by PinePi. They are never exposed for `wlan0`, arbitrary interfaces, or stations on third-party networks.

### WPA/WPA2 handshake capture

Handshake capture is part of the existing **Capture** page; there is no separate Handshake or Deauthentication menu. The intended workflow is:

1. Run Recon, choose an authorized WPA/WPA2 AP, and set it as the current target.
2. Open Capture, select a compatible free external adapter, and start **WPA/WPA2 Handshake** capture.
3. Wait passively, or optionally select a recently observed client and explicitly confirm **Force Reconnect**.
4. Watch the polled status progress through **Not captured** (red), **Partial** (orange), or **Full capture** (green).
5. Stop the capture manually and download its PCAPNG file or JSON summary from Capture History.

PinePi reserves the selected external adapter, enters monitor mode, tunes it to the target channel, and keeps `dumpcap` running while it inspects bounded EAPOL metadata with `tshark`. Analysis is scoped to the selected BSSID and client. Duplicate, retransmitted, out-of-order, malformed, unrelated, and truncated observations are handled conservatively; a full result requires a matching message pair from one client and replay exchange. The normal UI deliberately does not expose individual EAPOL message numbers or packet details.

The reconnect helper is optional: passive capture remains available when no client is known. It is accepted only for the exact live handshake capture, target BSSID, channel, reserved external adapter, and a client recently associated with that target in Recon or observed in captured EAPOL traffic. Each click and confirmation issues one fixed-argument, client-specific `aireplay-ng` request, capped server-side at 3 deauthentication frames and 15 seconds. There is no broadcast target, automatic retry, continuous mode, flood mode, or standalone endpoint that can start deauthentication without a matching active capture. The capture stays alive afterward so it can observe the reconnect.

## Architecture

The application uses Flask and SQLite. `OperationService` owns explicit operation lifecycles and cleanup; `ReservationRegistry` serializes ownership per physical interface; and `AdapterService` discovers live network state and capabilities. The Flask service runs as the unprivileged `pinepi` user. A separate root-owned Unix-socket helper exposes only fixed, validated wireless/network actions—never arbitrary commands. The helper never uses `shell=True`, accepts only Linux-valid interface names and PinePi-owned paths, and independently validates SSIDs, channels, passphrases, capture limits, and operation identifiers.

Transient process identities, interfaces requiring restoration, and nftables forwarding state are recorded in the root-owned `/var/lib/pinepi-system`. Startup reconciliation checks recorded command identities defensively, terminates only matching PinePi processes, restores external radios, removes only `pinepi_*` nftables tables, restores the prior forwarding value, clears ownership, and marks interrupted database sessions. `wlan0` is never treated as a stale audit radio.

The management WLAN is a separate systemd oneshot service. Its bounded boot-readiness loop waits for `wlan0`, clears the system-wide Wi-Fi soft block, verifies the management PHY, and raises the interface before reserving `wlan0` in NetworkManager and starting hostapd/dnsmasq. Failed early-boot attempts are retried by systemd with rate limiting. The web service is ordered after management startup but is not failed by a transient management-radio error; it remains available when the management address appears after recovery. A separate `pinepi-helper` service owns transient system processes and network changes. Test-AP startup does not report success until the radio reports AP mode and hostapd confirms both `ENABLED` and the requested SSID.

## Raspberry Pi installation

Use Raspberry Pi OS Bookworm or a comparable Debian system with NetworkManager. From a fresh checkout:

```bash
cd /path/to/PINEPI-demo
sudo bash scripts/install.sh
sudo systemctl status pinepi-management pinepi-helper pinepi --no-pager
iw dev
```

Then connect a client to the open `PinePi` WLAN and open `http://10.42.0.1:8080/`.

The installer installs only runtime tools used by the implementation: Python/venv, NetworkManager, rfkill, iw/iproute2, hostapd, dnsmasq, aircrack-ng, tshark/dumpcap, and nftables. It records then disables the distro-wide hostapd/dnsmasq units so PinePi's dedicated instances cannot conflict; uninstall restores units that were previously enabled or active. Application data lives under `/var/lib/pinepi`. Default storage values can be overridden in the service environment with `PINEPI_MAX_CAPTURE_BYTES` and `PINEPI_MIN_FREE_BYTES`.

After editing code, reinstall to refresh `/opt/pinepi`, or run a development instance in a venv:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
PINEPI_DATA_DIR="$PWD/.data" python -m pinepi
```

Root privileges are isolated to the helper and management-WLAN services. The web process has an empty capability bounding set. The shipped systemd sandboxes constrain filesystem access and Linux capabilities, while the helper protocol constrains accepted operation inputs.

## Verification

Hardware-independent checks:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
python -m compileall -q pinepi tests
bash -n scripts/install.sh scripts/uninstall.sh scripts/pinepi-management
git diff --check
```

On Raspberry Pi hardware, verify both radios and modes (`iw list`), management-WLAN recovery after reboot, Recon/Capture restoration to managed mode, hostapd/dnsmasq operation, client DHCP, Internet routing, nftables cleanup, storage-limit stops, and recovery after forcibly interrupting each operation.

For the management boot acceptance test, first run `sudo reboot` and do not issue any manual recovery command. After the Pi has completed booting, run:

```bash
rfkill list
sudo systemctl status pinepi-management pinepi-helper pinepi --no-pager -l
sudo journalctl -b -u pinepi-management --no-pager
iw dev
ip -br addr
nmcli device status
```

Expected results are an unblocked `wlan0` in AP mode with SSID `PinePi` and address `10.42.0.1/24`, all three PinePi services active, and `http://10.42.0.1:8080/` reachable from a client associated with the management WLAN.

## Uninstall

```bash
sudo bash scripts/uninstall.sh
```

Uninstall stops the web service first so its signal handler cleans transient operations, then stops the management WLAN and removes installed code/service configuration. It deliberately preserves user captures, sessions, logs, and the SQLite database in `/var/lib/pinepi`.
