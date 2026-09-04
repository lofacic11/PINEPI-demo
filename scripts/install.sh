#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/pinepi"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  python3 python3-venv iw iproute2 network-manager hostapd dnsmasq aircrack-ng tshark nftables

install -d -m 0755 "${INSTALL_DIR}" /etc/pinepi /usr/local/lib/pinepi
cp -a "${SOURCE_DIR}/pinepi" "${SOURCE_DIR}/pyproject.toml" "${SOURCE_DIR}/requirements.txt" "${INSTALL_DIR}/"
python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/pip" install --disable-pip-version-check --no-cache-dir "${INSTALL_DIR}"

install -m 0644 "${SOURCE_DIR}/config/management-hostapd.conf" /etc/pinepi/management-hostapd.conf
install -m 0644 "${SOURCE_DIR}/config/management-dnsmasq.conf" /etc/pinepi/management-dnsmasq.conf
install -m 0755 "${SOURCE_DIR}/scripts/pinepi-management" /usr/local/lib/pinepi/pinepi-management
install -m 0755 "${SOURCE_DIR}/scripts/pinepi-wait-helper" /usr/local/lib/pinepi/pinepi-wait-helper
install -m 0644 "${SOURCE_DIR}/systemd/pinepi-management.service" /etc/systemd/system/pinepi-management.service
install -m 0644 "${SOURCE_DIR}/systemd/pinepi-helper.service" /etc/systemd/system/pinepi-helper.service
install -m 0644 "${SOURCE_DIR}/systemd/pinepi.service" /etc/systemd/system/pinepi.service
getent group pinepi >/dev/null || groupadd --system pinepi
id -u pinepi >/dev/null 2>&1 || useradd --system --gid pinepi --home-dir /var/lib/pinepi --shell /usr/sbin/nologin pinepi
install -d -o pinepi -g pinepi -m 0750 /var/lib/pinepi
chown -R pinepi:pinepi /var/lib/pinepi
install -d -o root -g root -m 0700 /var/lib/pinepi-system

SERVICE_STATE=/var/lib/pinepi/preinstall-services.state
if [[ ! -e "${SERVICE_STATE}" ]]; then
  install -o root -g root -m 0600 /dev/null "${SERVICE_STATE}"
  for unit in hostapd dnsmasq; do
    enabled="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
    active="$(systemctl is-active "${unit}" 2>/dev/null || true)"
    printf '%s %s %s\n' "${unit}" "${enabled:-unknown}" "${active:-unknown}" >>"${SERVICE_STATE}"
  done
fi
chown root:root "${SERVICE_STATE}"
chmod 0600 "${SERVICE_STATE}"
systemctl disable --now hostapd dnsmasq 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now pinepi-management.service pinepi-helper.service pinepi.service

echo "PinePi installed. Connect to the open 'PinePi' WLAN and open http://10.42.0.1:8080/"
