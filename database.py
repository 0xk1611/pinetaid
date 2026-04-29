"""
PiNetAid – database.py
SQLite persistence layer: devices, traffic logs, AI results.
Thread-safe via check_same_thread=False + explicit locking.
"""

import sqlite3
import threading
import logging
from datetime import datetime

logger = logging.getLogger("pinetaid.database")

DB_PATH = "pinetaid.db"

# One global lock so concurrent threads don't interleave writes
_write_lock = threading.Lock()


class Database:
    """Lightweight wrapper around SQLite for PiNetAid."""

    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row          # rows behave like dicts
        self._conn.execute("PRAGMA journal_mode=WAL")  # better concurrency
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_schema()

    # ─── Schema ──────────────────────────────────────────────────────────────

    def _create_schema(self) -> None:
        with _write_lock:
            cur = self._conn.cursor()
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip        TEXT,
                    mac       TEXT UNIQUE NOT NULL,
                    vendor    TEXT DEFAULT 'Unknown',
                    -- TASK 5: running packet counter updated on every seen packet
                    packet_count INTEGER DEFAULT 0,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen  TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac        TEXT,
                    packet_type TEXT,
                    count      INTEGER DEFAULT 1,
                    window_start TIMESTAMP,
                    FOREIGN KEY(mac) REFERENCES devices(mac)
                );

                CREATE TABLE IF NOT EXISTS ai_results (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac         TEXT,
                    model       TEXT,
                    result      TEXT,
                    score       REAL,
                    reason      TEXT DEFAULT '',
                    -- TASK 3: severity level: Critical / High / Medium / Low
                    severity    TEXT DEFAULT 'Low',
                    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(mac) REFERENCES devices(mac)
                );

                -- TASK 4: track how many IPs each MAC has been seen with
                CREATE TABLE IF NOT EXISTS mac_ip_history (
                    id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac  TEXT NOT NULL,
                    ip   TEXT NOT NULL,
                    seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(mac, ip)
                );

                CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
                CREATE INDEX IF NOT EXISTS idx_traffic_mac ON traffic_logs(mac);
                CREATE INDEX IF NOT EXISTS idx_ai_mac      ON ai_results(mac);

                -- Anomaly lifecycle history (read-only from UI perspective).
                -- One active row per MAC (resolved_at IS NULL).
                -- Rows are marked resolved by the AI engine; hard-deleted only
                -- when the user explicitly deletes device data.
                CREATE TABLE IF NOT EXISTS ai_history (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac            TEXT NOT NULL,
                    ip             TEXT DEFAULT '',
                    vendor         TEXT DEFAULT '',
                    device_type    TEXT DEFAULT '',
                    score          REAL DEFAULT 0,
                    severity       TEXT DEFAULT 'Low',
                    confidence     TEXT DEFAULT '',
                    reason         TEXT DEFAULT '',
                    first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_updated   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved_at    TIMESTAMP DEFAULT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ai_history_mac ON ai_history(mac);
                CREATE INDEX IF NOT EXISTS idx_ai_history_res ON ai_history(resolved_at);
            """)
            self._conn.commit()

        # ── Safe migrations for databases created before this version ──────
        # Try each ALTER individually; ignore if column already exists.
        migrations = [
            "ALTER TABLE devices    ADD COLUMN packet_count INTEGER DEFAULT 0",
            "ALTER TABLE ai_results ADD COLUMN severity TEXT DEFAULT 'Low'",
            # TASK 1: subnet column — stores e.g. "192.168.1.0/24"
            "ALTER TABLE devices    ADD COLUMN subnet TEXT DEFAULT ''",
        ]
        for sql in migrations:
            try:
                self._conn.execute(sql)
                self._conn.commit()
            except Exception:
                pass  # column already exists — safe to ignore

    # ─── Devices ─────────────────────────────────────────────────────────────

    def upsert_device(self, ip: str, mac: str, vendor: str, last_seen: str,
                      subnet: str = "") -> None:
        """Insert or update a device record by MAC address."""
        with _write_lock:
            self._conn.execute("""
                INSERT INTO devices (ip, mac, vendor, last_seen, subnet)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip        = excluded.ip,
                    vendor    = excluded.vendor,
                    last_seen = excluded.last_seen,
                    subnet    = excluded.subnet
            """, (ip, mac, vendor, last_seen, subnet))
            # TASK 4: record every distinct IP this MAC has appeared with
            if ip and ip != "unknown":
                self._conn.execute("""
                    INSERT OR IGNORE INTO mac_ip_history (mac, ip) VALUES (?, ?)
                """, (mac, ip))
            self._conn.commit()

    def get_all_devices(self, subnet: str = None) -> list[dict]:
        """Return devices including packet_count for behavior-based type detection (TASK 3)."""
        cols = "ip, mac, vendor, subnet, first_seen, last_seen, COALESCE(packet_count,0) AS packet_count"
        if subnet:
            cur = self._conn.execute(
                f"SELECT {cols} FROM devices WHERE subnet = ? ORDER BY last_seen DESC",
                (subnet,)
            )
        else:
            cur = self._conn.execute(
                f"SELECT {cols} FROM devices ORDER BY last_seen DESC"
            )
        return [dict(row) for row in cur.fetchall()]

    def get_subnets(self) -> list[str]:
        """TASK 1: Return all distinct non-empty subnets seen in the DB."""
        cur = self._conn.execute(
            "SELECT DISTINCT subnet FROM devices "
            "WHERE subnet IS NOT NULL AND subnet != '' ORDER BY subnet"
        )
        return [row[0] for row in cur.fetchall()]

    def get_device(self, mac: str) -> dict | None:
        cur = self._conn.execute(
            "SELECT ip, mac, vendor, first_seen, last_seen FROM devices WHERE mac = ?", (mac,)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def device_count(self, subnet: str = None) -> int:
        """TASK 1: count devices, optionally scoped to a subnet."""
        if subnet:
            cur = self._conn.execute(
                "SELECT COUNT(*) FROM devices WHERE subnet = ?", (subnet,))
        else:
            cur = self._conn.execute("SELECT COUNT(*) FROM devices")
        return cur.fetchone()[0]

    # ─── Traffic Logs ────────────────────────────────────────────────────────

    def log_traffic(self, mac: str, packet_type: str, count: int = 1,
                    window_start: str = None) -> None:
        window_start = window_start or datetime.utcnow().isoformat()
        with _write_lock:
            self._conn.execute("""
                INSERT INTO traffic_logs (mac, packet_type, count, window_start)
                VALUES (?, ?, ?, ?)
            """, (mac, packet_type, count, window_start))
            self._conn.commit()

    def get_traffic_for_device(self, mac: str, limit: int = 100) -> list[dict]:
        cur = self._conn.execute("""
            SELECT packet_type, count, window_start
            FROM traffic_logs WHERE mac = ?
            ORDER BY window_start DESC LIMIT ?
        """, (mac, limit))
        return [dict(row) for row in cur.fetchall()]

    def get_recent_traffic_counts(self, limit: int = 200) -> list[dict]:
        """Fetch recent (mac, count) rows for anomaly detection input."""
        cur = self._conn.execute("""
            SELECT mac, SUM(count) as total
            FROM traffic_logs
            GROUP BY mac
            ORDER BY total DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cur.fetchall()]

    def get_recent_traffic_counts_window(self, minutes: int = 5,
                                         limit: int = 200) -> list[dict]:
        """
        TASK 4: Like get_recent_traffic_counts but scoped to a specific time window.
        Used by the behavior-based anomaly rule to compare short-term vs long-term rates.
        """
        cur = self._conn.execute("""
            SELECT mac, SUM(count) as total
            FROM traffic_logs
            WHERE window_start >= datetime('now', ?)
            GROUP BY mac
            ORDER BY total DESC
            LIMIT ?
        """, (f"-{minutes} minutes", limit))
        return [dict(row) for row in cur.fetchall()]

    # ─── AI Results ──────────────────────────────────────────────────────────

    def save_ai_result(self, mac: str, model: str, result: str,
                       score: float, reason: str = "",
                       severity: str = "Low") -> None:
        """
        Insert anomaly result, or UPDATE the existing row if the same MAC + rule
        has already fired within the last 10 minutes (prevents duplicates).
        """
        # Extract the rule-type prefix up to the first colon.
        # e.g. "ARP flood: 55 packets" → "ARP flood"
        reason_key = reason.split(":")[0].strip() if reason else ""

        with _write_lock:
            # TASK 2: check for a recent duplicate with the SAME rule prefix.
            # Use "reason_key: %" pattern so "Traffic spike" never matches "Traffic".
            existing = self._conn.execute("""
                SELECT id FROM ai_results
                WHERE mac = ?
                  AND result = 'anomaly'
                  AND (reason LIKE ? OR reason = ?)
                  AND created_at >= datetime('now', '-10 minutes')
                LIMIT 1
            """, (mac, f"{reason_key}: %", reason_key)).fetchone()

            if existing:
                # Duplicate within 10 min — update score/reason/time, don't insert
                self._conn.execute("""
                    UPDATE ai_results
                    SET score      = ?,
                        reason     = ?,
                        severity   = ?,
                        created_at = datetime('now')
                    WHERE id = ?
                """, (score, reason, severity, existing["id"]))
            else:
                self._conn.execute("""
                    INSERT INTO ai_results (mac, model, result, score, reason, severity)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (mac, model, result, score, reason, severity))

            self._conn.commit()

    def get_anomalies(self, limit: int = 50, subnet: str = None) -> list[dict]:
        """INNER JOIN excludes orphan rows; optional subnet filter."""
        if subnet:
            cur = self._conn.execute("""
                SELECT a.mac, d.ip, d.vendor, a.model, a.result,
                       a.score, a.reason, a.severity, a.created_at
                FROM ai_results a
                INNER JOIN devices d ON a.mac = d.mac
                WHERE a.result = 'anomaly' AND d.subnet = ?
                ORDER BY a.created_at DESC LIMIT ?
            """, (subnet, limit))
        else:
            cur = self._conn.execute("""
                SELECT a.mac, d.ip, d.vendor, a.model, a.result,
                       a.score, a.reason, a.severity, a.created_at
                FROM ai_results a
                INNER JOIN devices d ON a.mac = d.mac
                WHERE a.result = 'anomaly'
                ORDER BY a.created_at DESC LIMIT ?
            """, (limit,))
        return [dict(row) for row in cur.fetchall()]

    def get_all_ai_results(self, limit: int = 100) -> list[dict]:
        cur = self._conn.execute("""
            SELECT a.mac, d.ip, d.vendor, a.model, a.result,
                   a.score, a.reason, a.severity, a.created_at
            FROM ai_results a
            LEFT JOIN devices d ON a.mac = d.mac
            ORDER BY a.created_at DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cur.fetchall()]

    def anomaly_count(self, subnet: str = None) -> int:
        """TASK 1: count anomalies, optionally scoped to a subnet."""
        if subnet:
            cur = self._conn.execute("""
                SELECT COUNT(*) FROM ai_results a
                JOIN devices d ON a.mac = d.mac
                WHERE a.result = 'anomaly' AND d.subnet = ?
            """, (subnet,))
        else:
            cur = self._conn.execute(
                "SELECT COUNT(*) FROM ai_results WHERE result = 'anomaly'"
            )
        return cur.fetchone()[0]

    # ─── TASK 4: Rule-based anomaly helpers ──────────────────────────────────

    def get_arp_counts_last_minutes(self, minutes: int = 5) -> list[dict]:
        """Return ARP packet totals per MAC in the last N minutes."""
        cur = self._conn.execute("""
            SELECT mac, SUM(count) as total
            FROM traffic_logs
            WHERE packet_type = 'ARP'
              AND window_start >= datetime('now', ? || ' minutes')
            GROUP BY mac
            ORDER BY total DESC
        """, (f"-{minutes}",))
        return [dict(row) for row in cur.fetchall()]

    def get_ip_count_per_mac(self) -> list[dict]:
        """Return how many distinct IPs each MAC has been seen with."""
        cur = self._conn.execute("""
            SELECT mac, COUNT(DISTINCT ip) as ip_count
            FROM mac_ip_history
            GROUP BY mac
            HAVING ip_count > 1
        """)
        return [dict(row) for row in cur.fetchall()]

    def get_new_devices_last_minutes(self, minutes: int = 10) -> list[dict]:
        """Return devices first seen within the last N minutes."""
        cur = self._conn.execute("""
            SELECT mac, ip, vendor, first_seen
            FROM devices
            WHERE first_seen >= datetime('now', ? || ' minutes')
        """, (f"-{minutes}",))
        return [dict(row) for row in cur.fetchall()]

    # ─── TASK 6: Extra feature helpers ───────────────────────────────────────

    def increment_packet_count(self, mac: str, packet_type: str = "ARP") -> None:
        """
        TASK 5: Increment per-device packet counter directly on the devices
        table. Called from capture.py on every seen packet so that
        Top Active always has data even if traffic_logs is empty.
        Uses a single UPDATE — no lock needed (SQLite serialises writes).
        """
        with _write_lock:
            self._conn.execute("""
                UPDATE devices
                SET packet_count = COALESCE(packet_count, 0) + 1
                WHERE mac = ?
            """, (mac,))
            self._conn.commit()

    def get_top_active_devices(self, limit: int = 10, subnet: str = None) -> list[dict]:
        """Return most active devices; optional subnet filter."""
        if subnet:
            cur = self._conn.execute("""
                SELECT d.mac, d.ip, d.vendor,
                       COALESCE(tl.total, 0) + COALESCE(d.packet_count, 0) AS total_packets
                FROM devices d
                LEFT JOIN (
                    SELECT mac, SUM(count) AS total FROM traffic_logs GROUP BY mac
                ) tl ON d.mac = tl.mac
                WHERE d.subnet = ?
                ORDER BY total_packets DESC LIMIT ?
            """, (subnet, limit))
        else:
            cur = self._conn.execute("""
                SELECT d.mac, d.ip, d.vendor,
                       COALESCE(tl.total, 0) + COALESCE(d.packet_count, 0) AS total_packets
                FROM devices d
                LEFT JOIN (
                    SELECT mac, SUM(count) AS total FROM traffic_logs GROUP BY mac
                ) tl ON d.mac = tl.mac
                ORDER BY total_packets DESC LIMIT ?
            """, (limit,))
        return [dict(row) for row in cur.fetchall()]

    def get_network_health(self, subnet: str = None) -> dict:
        """
        TASK 1: Network health scoped to a subnet when provided.
        """
        anomalies = self.anomaly_count(subnet=subnet)
        new_devs  = len(self.get_new_devices_last_minutes(10))

        if anomalies >= 3:
            status = "Critical"
            color  = "red"
        elif anomalies >= 1 or new_devs >= 5:
            status = "Warning"
            color  = "yellow"
        else:
            status = "Good"
            color  = "green"

        return {"status": status, "color": color,
                "anomaly_count": anomalies, "new_devices": new_devs}

    def get_device_types(self, subnet: str = None) -> list[dict]:
        """Classify devices; optional subnet filter."""
        where = "WHERE d.subnet = ?" if subnet else ""
        params = (subnet,) if subnet else ()
        cur = self._conn.execute(f"""
            SELECT d.mac, d.ip, d.vendor,
                   COALESCE(d.packet_count, 0) AS pkt,
                   SUM(CASE WHEN t.packet_type='ARP'  THEN t.count ELSE 0 END) AS arp_count,
                   SUM(CASE WHEN t.packet_type='DNS'  THEN t.count ELSE 0 END) AS dns_count,
                   SUM(t.count) AS log_total
            FROM devices d
            LEFT JOIN traffic_logs t ON d.mac = t.mac
            {where}
            GROUP BY d.mac
        """, params)

        # Keyword lists for vendor-based classification
        IOT_VENDORS    = ["raspberry", "arduino", "esp", "shelly", "tuya",
                          "sonos", "ring", "nest", "wemo", "philips hue",
                          "lifx", "broadlink", "tasmota", "ewelink"]
        MOBILE_VENDORS = ["apple", "samsung", "oneplus", "huawei", "oppo",
                          "vivo", "xiaomi", "realme", "nothing", "google pixel"]
        PC_VENDORS     = ["intel", "dell", "hp ", "lenovo", "asus", "acer",
                          "microsoft", "msi ", "gigabyte", "asrock", "supermicro"]
        NETWORK_VENDORS= ["cisco", "ubiquiti", "netgear", "tp-link", "d-link",
                          "mikrotik", "juniper", "aruba", "zyxel", "fortinet"]

        results = []
        for row in cur.fetchall():
            row       = dict(row)
            vendor    = (row["vendor"] or "").lower()
            arp       = row["arp_count"] or 0
            dns       = row["dns_count"] or 0
            log_total = row["log_total"] or 0
            # Use packet_count as a proxy when traffic_logs is empty/thin
            total     = log_total if log_total > 0 else row["pkt"]

            # 1. Vendor keyword match (most reliable)
            if any(k in vendor for k in IOT_VENDORS):
                dtype = "IoT Device"
            elif any(k in vendor for k in MOBILE_VENDORS):
                dtype = "Mobile Device"
            elif any(k in vendor for k in PC_VENDORS):
                dtype = "PC / Laptop"
            elif any(k in vendor for k in NETWORK_VENDORS):
                dtype = "Network Device"

            # 2. Behaviour heuristics (no vendor match) — T6: never return Unknown
            elif total == 0:
                dtype = "IoT Device"        # T6: unseen traffic → assume IoT/quiet
            elif arp > 0 and log_total > 0 and arp / log_total > 0.5:
                dtype = "Windows PC"        # Windows probes ARP constantly
            elif dns > 0 and log_total > 0 and dns / log_total > 0.4:
                dtype = "Mobile Device"     # phones resolve DNS frequently
            elif total > 100:
                dtype = "PC / Server"       # high volume = computer or server
            elif total < 15:
                dtype = "IoT Device"        # very low traffic = embedded device
            else:
                dtype = "Network Device"    # T6: medium ARP traffic → likely a switch/AP

            results.append({
                "mac": row["mac"], "ip": row["ip"],
                "vendor": row["vendor"], "device_type": dtype,
            })
        return results

    def delete_by_subnet(self, subnet: str) -> dict:
        """
        TASK 1: Delete ALL data for a subnet from every related table.
        If subnet == "All" → wipe everything from all tables.
        Deletion order respects FK constraints: child tables first, devices last.
        """
        with _write_lock:
            if subnet == "All":
                # Wipe every table completely
                cur_a  = self._conn.execute("DELETE FROM ai_results")
                cur_t  = self._conn.execute("DELETE FROM traffic_logs")
                self._conn.execute("DELETE FROM mac_ip_history")
                self._conn.execute("DELETE FROM ai_history")
                cur_d  = self._conn.execute("DELETE FROM devices")
            else:
                # Sub-select the MACs in this subnet once; re-use for all tables
                macs = [r[0] for r in self._conn.execute(
                    "SELECT mac FROM devices WHERE subnet = ?", (subnet,)
                ).fetchall()]

                if not macs:
                    self._conn.commit()
                    return {"devices": 0, "anomalies": 0, "traffic": 0}

                ph = ",".join("?" * len(macs))
                cur_a = self._conn.execute(
                    f"DELETE FROM ai_results     WHERE mac IN ({ph})", macs)
                cur_t = self._conn.execute(
                    f"DELETE FROM traffic_logs   WHERE mac IN ({ph})", macs)
                self._conn.execute(
                    f"DELETE FROM mac_ip_history WHERE mac IN ({ph})", macs)
                self._conn.execute(
                    f"DELETE FROM ai_history     WHERE mac IN ({ph})", macs)
                cur_d = self._conn.execute(
                    "DELETE FROM devices WHERE subnet = ?", (subnet,))

            self._conn.commit()

        return {
            "devices":   cur_d.rowcount,
            "anomalies": cur_a.rowcount,
            "traffic":   cur_t.rowcount,
        }

    # keep clear_subnet_data as a thin alias so existing callers still work
    def clear_subnet_data(self, subnet: str) -> dict:
        return self.delete_by_subnet(subnet)

    def get_anomaly_history(self, limit: int = 100,
                            subnet: str = None) -> list[dict]:
        """
        Return resolved anomaly history rows only (resolved_at IS NOT NULL).
        Active anomalies are in ai_results — not here.
        Joins to devices to get the current IP for each MAC.
        """
        if subnet:
            cur = self._conn.execute("""
                SELECT h.id, h.mac,
                       COALESCE(d.ip, h.ip, '') AS ip,
                       COALESCE(d.vendor, h.vendor, '') AS vendor,
                       h.device_type,
                       h.score, h.severity, h.reason,
                       h.first_detected, h.last_updated, h.resolved_at
                FROM ai_history h
                LEFT JOIN devices d ON h.mac = d.mac
                WHERE h.resolved_at IS NOT NULL
                  AND h.mac IN (
                      SELECT mac FROM devices WHERE subnet = ?
                  )
                ORDER BY h.last_updated DESC
                LIMIT ?
            """, (subnet, limit))
        else:
            cur = self._conn.execute("""
                SELECT h.id, h.mac,
                       COALESCE(d.ip, h.ip, '') AS ip,
                       COALESCE(d.vendor, h.vendor, '') AS vendor,
                       h.device_type,
                       h.score, h.severity, h.reason,
                       h.first_detected, h.last_updated, h.resolved_at
                FROM ai_history h
                LEFT JOIN devices d ON h.mac = d.mac
                WHERE h.resolved_at IS NOT NULL
                ORDER BY h.last_updated DESC
                LIMIT ?
            """, (limit,))
        return [dict(row) for row in cur.fetchall()]

    def delete_anomaly(self, mac: str) -> None:
        """Remove all active anomaly rows for a MAC from ai_results."""
        with _write_lock:
            self._conn.execute(
                "DELETE FROM ai_results WHERE mac = ? AND result = 'anomaly'",
                (mac,),
            )
            self._conn.commit()

    def save_ai_history(self, mac: str, ip: str = "", vendor: str = "",
                        device_type: str = "", score: float = 0.0,
                        severity: str = "Low", reason: str = "") -> None:
        """
        Upsert a staging history row for an active anomaly.
        resolved_at stays NULL while the device is still flagged.
        When the device clears, resolve_history() sets resolved_at,
        which is when the row becomes visible in the History tab.
        """
        with _write_lock:
            existing = self._conn.execute(
                "SELECT id FROM ai_history WHERE mac = ? AND resolved_at IS NULL LIMIT 1",
                (mac,),
            ).fetchone()
            if existing:
                self._conn.execute("""
                    UPDATE ai_history
                    SET ip=?, vendor=?, device_type=?, score=?,
                        severity=?, reason=?, last_updated=datetime('now')
                    WHERE id=?
                """, (ip, vendor, device_type, score, severity, reason, existing["id"]))
            else:
                self._conn.execute("""
                    INSERT INTO ai_history
                        (mac, ip, vendor, device_type, score, severity, reason,
                         first_detected, last_updated, resolved_at)
                    VALUES (?,?,?,?,?,?,?,datetime('now'),datetime('now'),NULL)
                """, (mac, ip, vendor, device_type, score, severity, reason))
            self._conn.commit()

    def resolve_history(self, macs: list) -> None:
        """
        Mark history rows resolved for devices that are no longer anomalous.
        Once resolved_at is set, the row becomes visible in the History tab.
        """
        if not macs:
            return
        ph = ",".join("?" * len(macs))
        with _write_lock:
            self._conn.execute(
                f"UPDATE ai_history SET resolved_at=datetime('now')"
                f" WHERE mac IN ({ph}) AND resolved_at IS NULL",
                list(macs),
            )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()
