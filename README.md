# PiNetAid

Offline, passive network monitoring and anomaly detection for Raspberry Pi 4.

---

## File Structure

```
pinetaid/
├── main.py          ← Entry point (run this)
├── capture.py       ← Passive packet capture (ARP + DHCP)
├── database.py      ← SQLite persistence layer
├── ai.py            ← Anomaly detection + clustering
├── diagnostics.py   ← Ping / DNS / port checks
├── dashboard.py     ← Flask web dashboard
├── auth.py          ← Login / bcrypt credential store
├── oui.py           ← Offline MAC vendor lookup
├── requirements.txt
└── data/
    ├── oui.txt          ← OUI database (download separately)
    └── credentials.json ← Created on first run
```

---

## Installation

```bash
# 1. Install system dependencies
sudo apt update && sudo apt install -y python3-pip tcpdump

# 2. Install Python packages
pip3 install -r requirements.txt

# 3. (Optional) Download OUI database for vendor lookups
mkdir -p data
curl -o data/oui.txt https://standards-oui.ieee.org/oui/oui.txt
```

---

## Usage

```bash
# Run as root (required for raw packet capture)
sudo python3 main.py

# Specify interface
sudo python3 main.py --interface eth0

# Dashboard only (no capture)
python3 main.py --no-capture

# Custom port
sudo python3 main.py --port 8080
```

Open the dashboard: `http://<pi-ip>:5000`

On first run, you will be prompted to create an admin account.

---

## Architecture

```
Network Traffic
     │
     ▼
capture.py  ←── ARP + DHCP sniff (passive, no scanning)
     │
     ├──→ oui.py       (vendor lookup)
     │
     ▼
database.py ←── SQLite (devices, traffic_logs, ai_results)
     │
     ├──→ ai.py         (Isolation Forest + K-Means)
     │
     ▼
dashboard.py ←── Flask UI (login, devices, anomalies, diagnostics)
```

---

## API Endpoints (JSON)

| Endpoint          | Description              |
|-------------------|--------------------------|
| `GET /api/devices`   | All captured devices  |
| `GET /api/anomalies` | Logged anomalies      |
| `GET /api/status`    | Device count + status |

All endpoints require login session.

---

## Constraints

- Passive only — no active scanning or probing
- No external network calls
- Runs fully offline on Raspberry Pi 4 (4 GB)
- SQLite only — no external database
