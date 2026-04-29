#!/bin/bash
# PiNetAid – install_service.sh
# TASK 7: Install and enable the systemd service so PiNetAid starts on boot.
#
# Usage:
#   chmod +x install_service.sh
#   sudo ./install_service.sh
# ─────────────────────────────────────────────────────────────────────────────

set -e   # exit immediately on any error

SERVICE_FILE="pinetaid.service"
DEST="/etc/systemd/system/pinetaid.service"
PROJECT_DIR="$(pwd)"   # assumes you run this from the pinetaid/ directory

echo "=== PiNetAid Service Installer ==="

# 1. Confirm running as root
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run as root (sudo ./install_service.sh)"
  exit 1
fi

# 2. Patch WorkingDirectory and ExecStart to use actual current directory
echo "[1/4] Setting project path to: $PROJECT_DIR"
sed "s|WorkingDirectory=.*|WorkingDirectory=$PROJECT_DIR|g;
     s|ExecStart=.*|ExecStart=/home/pin/Desktop/pinetaid/venv/bin/python $PROJECT_DIR/main.py --interface wlan0|g" \
    "$SERVICE_FILE" > "$DEST"

# 3. Reload systemd to pick up the new unit file
echo "[2/4] Reloading systemd daemon..."
systemctl daemon-reload

# 4. Enable service (start on boot)
echo "[3/4] Enabling pinetaid.service..."
systemctl enable pinetaid.service

# 5. Start service now
echo "[4/4] Starting pinetaid.service..."
systemctl start pinetaid.service

echo ""
echo "✓ PiNetAid is now running and will auto-start on every boot."
echo ""
echo "Useful commands:"
echo "  sudo systemctl status  pinetaid   # check status"
echo "  sudo systemctl stop    pinetaid   # stop"
echo "  sudo systemctl restart pinetaid   # restart"
echo "  journalctl -u pinetaid -f         # follow live logs"
echo ""
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):5000"
