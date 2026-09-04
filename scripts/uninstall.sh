#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this uninstaller with sudo." >&2
  exit 1
fi

# Stopping pinepi first lets its SIGTERM handler stop transient Recon/AP/Capture jobs.
systemctl disable --now pinepi.service 2>/dev/null || true
if [[ -x /opt/pinepi/.venv/bin/python ]]; then
  PINEPI_DATA_DIR=/var/lib/pinepi PINEPI_HELPER_SOCKET=/run/pinepi/helper.sock \
    /opt/pinepi/.venv/bin/python -c 'from pinepi import create_app; create_app()' 2>/dev/null || true
fi
systemctl disable --now pinepi-helper.service 2>/dev/null || true
if [[ -x /opt/pinepi/.venv/bin/python ]]; then
  PINEPI_DATA_DIR=/var/lib/pinepi PINEPI_HELPER_SOCKET= \
    PINEPI_RUNTIME_DIR=/var/lib/pinepi-system /opt/pinepi/.venv/bin/python \
    -c 'from pinepi import create_app; create_app()' 2>/dev/null || true
fi
systemctl disable --now pinepi-management.service 2>/dev/null || true
rm -f /etc/systemd/system/pinepi.service /etc/systemd/system/pinepi-helper.service /etc/systemd/system/pinepi-management.service
rm -f /usr/local/lib/pinepi/pinepi-management /usr/local/lib/pinepi/pinepi-wait-helper
rm -f /etc/pinepi/management-hostapd.conf /etc/pinepi/management-dnsmasq.conf
rmdir /etc/pinepi /usr/local/lib/pinepi 2>/dev/null || true
rm -rf /opt/pinepi
rm -rf /var/lib/pinepi-system
systemctl daemon-reload

SERVICE_STATE=/var/lib/pinepi/preinstall-services.state
if [[ -f "${SERVICE_STATE}" ]]; then
  while read -r unit enabled active; do
    case "${unit}" in
      hostapd|dnsmasq) ;;
      *) continue ;;
    esac
    if [[ "${enabled}" == "enabled" ]]; then
      systemctl enable "${unit}" 2>/dev/null || true
    fi
    if [[ "${active}" == "active" ]]; then
      systemctl start "${unit}" 2>/dev/null || true
    fi
  done <"${SERVICE_STATE}"
  rm -f "${SERVICE_STATE}"
fi

echo "PinePi was uninstalled. Captures and session data remain in /var/lib/pinepi."
