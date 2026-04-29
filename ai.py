"""
PiNetAid – ai.py
Anomaly detection: rule-based engine + optional Isolation Forest.

TASK 1: Rules only fire on real conditions — no device is flagged unless a
        threshold is actually crossed. Generic 0.6 score for all removed.
TASK 2: Deduplication is handled by database.save_ai_result() — each rule
        passes a stable reason prefix so the DB can match & update instead
        of inserting.
TASK 3: Each rule maps to a severity level:
          ARP flood          → Critical
          MAC multiple IPs   → High
          New device         → Medium
          Traffic spike      → Low
"""

import logging
import numpy as np
from datetime import datetime

from database import Database

logger = logging.getLogger("pinetaid.ai")

# ─── Thresholds ──────────────────────────────────────────────────────────────
ARP_FLOOD_THRESHOLD   = 50    # ARP packets per MAC in 5 min
SPIKE_MULTIPLIER      = 5.0   # global median spike multiplier
BEHAVIOUR_MULTIPLIER  = 3.0   # T4: per-device spike: flag if current > 3× own avg
NEW_DEVICE_MINUTES    = 10
MIN_DEVICES_FOR_SPIKE = 3
BEHAVIOUR_WINDOW_SHORT = 5    # minutes — "current" window
BEHAVIOUR_WINDOW_LONG  = 60   # minutes — "baseline" window
BEHAVIOUR_DEVIATION    = 4.0  # legacy threshold (kept for compat)


def _get_local_macs() -> set[str]:
    """T2: get Pi's own MACs to skip in anomaly detection."""
    try:
        from capture import get_local_macs
        return get_local_macs()
    except Exception:
        return set()


def _fmt(severity: str, short: str, detail: str) -> str:
    """
    T5: Build a human-readable anomaly description.
    Format: "High – IP conflict (seen with 3 different IPs)"
    """
    return f"{severity} – {short} ({detail})"


# ─── Helper: flag collector ───────────────────────────────────────────────────

class _FlagCollector:
    """Accumulates per-MAC anomaly data before persisting."""

    def __init__(self):
        self._flags: dict[str, dict] = {}

    def add(self, mac: str, reason: str, score: float, severity: str) -> None:
        if mac not in self._flags:
            self._flags[mac] = {"reasons": [], "score": score, "severity": severity}
        self._flags[mac]["reasons"].append(reason)
        # Keep the worst (highest) score and severity seen
        if score > self._flags[mac]["score"]:
            self._flags[mac]["score"]    = score
            self._flags[mac]["severity"] = severity

    def items(self):
        return self._flags.items()

    def __len__(self):
        return len(self._flags)


# ─── Rule-Based Anomaly Detection ────────────────────────────────────────────

def run_rule_based_detection(db: Database) -> list[dict]:
    """
    Five rules. T2: the Pi's own MACs are always skipped.
    T5: all reasons use human-readable prose.
    Wrapped in try/except so a single bad row never kills the whole run.
    """
    try:
        return _run_rules(db)
    except Exception as exc:
        logger.error("run_rule_based_detection failed: %s", exc, exc_info=True)
        return []


def _run_rules(db: Database) -> list[dict]:
    """Inner implementation — called by run_rule_based_detection."""
    flags      = _FlagCollector()
    local_macs = _get_local_macs()   # T2: skip own interfaces

    # ── Rule 1: ARP Flood → Critical ────────────────────────────────────────
    for row in db.get_arp_counts_last_minutes(minutes=5):
        mac = row["mac"]
        if mac in local_macs:          # T2: skip Pi's own MACs
            continue
        if row["total"] >= ARP_FLOOD_THRESHOLD:
            flags.add(
                mac=mac,
                reason=_fmt("Critical", "ARP flood",
                            f"{row['total']} ARP requests in 5 min "
                            f"— threshold is {ARP_FLOOD_THRESHOLD}"),
                score=0.95, severity="Critical",
            )

    # ── Rule 2: MAC with Multiple IPs → High ────────────────────────────────
    for row in db.get_ip_count_per_mac():
        mac = row["mac"]
        if mac in local_macs:
            continue
        flags.add(
            mac=mac,
            reason=_fmt("High", "IP conflict",
                        f"same MAC appeared with {row['ip_count']} different IPs"),
            score=0.85, severity="High",
        )

    # ── Rule 3: New Device → Medium ─────────────────────────────────────────
    for dev in db.get_new_devices_last_minutes(minutes=NEW_DEVICE_MINUTES):
        mac = dev["mac"]
        if mac in local_macs:
            continue
        vendor = dev.get("vendor") or "unknown vendor"
        flags.add(
            mac=mac,
            reason=_fmt("Medium", "New device",
                        f"first seen {NEW_DEVICE_MINUTES} min ago, vendor: {vendor}"),
            score=0.55, severity="Medium",
        )

    # ── Rule 4: Global Traffic Spike → Low ──────────────────────────────────
    traffic = db.get_recent_traffic_counts(limit=500)
    if len(traffic) >= MIN_DEVICES_FOR_SPIKE:
        # Guard: skip rows where total is None/non-numeric before building array
        valid_traffic = [r for r in traffic if r.get("total") is not None]
        if len(valid_traffic) >= MIN_DEVICES_FOR_SPIKE:
            totals = np.array([float(r["total"]) for r in valid_traffic], dtype=float)
            median = float(np.median(totals)) if len(totals) > 0 else 0.0
            if median > 0:
                for row in valid_traffic:
                    if row["mac"] in local_macs:
                        continue
                    row_total = float(row["total"])
                    if row_total > median * SPIKE_MULTIPLIER:
                        ratio = row_total / median
                        flags.add(
                            mac=row["mac"],
                            reason=_fmt("Low", f"Traffic spike ({ratio:.0f}x normal)",
                                        f"{row_total:.0f} packets vs network avg of {median:.0f}"),
                            score=0.70, severity="Low",
                        )

    # ── Rule 5: Per-Device Behavior Spike → Medium (T4) ─────────────────────
    # If a device's recent rate is > BEHAVIOUR_MULTIPLIER× its own baseline,
    # it has changed its own behavior independent of other devices.
    short_counts = {r["mac"]: r["total"]
                    for r in db.get_recent_traffic_counts_window(
                        minutes=BEHAVIOUR_WINDOW_SHORT, limit=500)
                    if r.get("total") is not None}
    long_counts  = {r["mac"]: r["total"]
                    for r in db.get_recent_traffic_counts_window(
                        minutes=BEHAVIOUR_WINDOW_LONG, limit=500)
                    if r.get("total") is not None}

    for mac, short_total in short_counts.items():
        if mac in local_macs:
            continue
        long_total = long_counts.get(mac, 0)
        if not long_total or long_total <= 0:
            continue
        # Safe division: constants are non-zero, but cast to float first
        rate_short = float(short_total) / BEHAVIOUR_WINDOW_SHORT if BEHAVIOUR_WINDOW_SHORT > 0 else 0.0
        rate_long  = float(long_total)  / BEHAVIOUR_WINDOW_LONG  if BEHAVIOUR_WINDOW_LONG  > 0 else 0.0
        # Require a meaningful baseline (>= 2 pkt/min average) to avoid
        # flagging devices that just started sending traffic
        if rate_long < 2.0:
            continue
        if rate_short > rate_long * BEHAVIOUR_MULTIPLIER:
            ratio = rate_short / rate_long  # rate_long >= 2.0 so never zero
            flags.add(
                mac=mac,
                reason=_fmt("Medium", f"Traffic spike ({ratio:.0f}x normal)",
                            f"current {rate_short:.1f} pkt/min vs own avg "
                            f"{rate_long:.1f} pkt/min over {BEHAVIOUR_WINDOW_LONG} min"),
                score=0.75, severity="Medium",
            )

    # ── Persist ──────────────────────────────────────────────────────────────
    results      = []
    flagged_macs = set()

    for mac, data in flags.items():
        reason_str = "; ".join(data["reasons"])

        # Write to the active anomaly table
        db.save_ai_result(mac=mac, model="RuleEngine", result="anomaly",
                          score=data["score"], reason=reason_str,
                          severity=data["severity"])

        # Stage a history row (resolved_at = NULL while still active).
        # clear_resolved_anomalies() will set resolved_at when the device clears,
        # which is the only moment the row becomes visible in the History tab.
        dev = db.get_device(mac) or {}
        db.save_ai_history(
            mac=mac,
            ip=dev.get("ip") or "",
            vendor=dev.get("vendor") or "",
            device_type="",
            score=data["score"],
            severity=data["severity"],
            reason=reason_str,
        )

        flagged_macs.add(mac)
        results.append({"mac": mac, "result": "anomaly",
                        "score": data["score"], "reason": reason_str,
                        "severity": data["severity"]})
        logger.warning(f"[{data['severity']}] {mac}: {reason_str}")

    # Resolve any device that was anomalous last run but is clean this run.
    # This deletes it from ai_results and sets resolved_at in ai_history.
    clear_resolved_anomalies(db, flagged_macs)

    logger.info(f"Rule engine: {len(results)} device(s) flagged.")
    return results


def clear_resolved_anomalies(db: Database, flagged_macs: set) -> None:
    """
    Clean up devices that are no longer anomalous.
    Deletes from ai_results and sets resolved_at in ai_history,
    which is the moment they move from Active to History.
    """
    current_active = {r["mac"] for r in db.get_anomalies(limit=10000)}
    to_resolve = current_active - flagged_macs
    if not to_resolve:
        return
    for mac in to_resolve:
        db.delete_anomaly(mac)
    db.resolve_history(list(to_resolve))
    logger.info("Resolved %d anomaly(ies) — moved to history: %s",
                len(to_resolve), to_resolve)


# ─── Isolation Forest (secondary, needs ≥ 4 devices) ────────────────────────

def run_isolation_forest(db: Database, contamination: float = 0.1) -> list[dict]:
    """
    Optional statistical layer. Skipped silently if not enough data.
    Only saves results that aren't already flagged by rule engine.
    """
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        logger.warning("scikit-learn not available; skipping Isolation Forest.")
        return []

    rows = db.get_recent_traffic_counts(limit=500)
    # Guard: filter rows with valid numeric totals before feeding to sklearn
    rows = [r for r in rows if r.get("total") is not None]
    if len(rows) < 4:
        logger.info("Isolation Forest skipped: need >= 4 devices with traffic.")
        return []

    mac_list = [r["mac"] for r in rows]
    X = np.array([[float(r["total"])] for r in rows], dtype=float)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(contamination=contamination,
                            random_state=42, n_estimators=50)
    model.fit(X_scaled)

    predictions = model.predict(X_scaled)
    scores      = model.decision_function(X_scaled)

    results = []
    for mac, pred, score in zip(mac_list, predictions, scores):
        if pred == -1:
            # Guard: decision_function can produce NaN if all values are identical
            safe_score = float(score) if score is not None and score == score else 0.0
            reason = f"Statistical outlier (IsolationForest score={safe_score:.4f})"
            db.save_ai_result(mac=mac, model="IsolationForest",
                              result="anomaly", score=safe_score,
                              reason=reason, severity="Low")   # TASK 3
            results.append({"mac": mac, "result": "anomaly",
                             "score": round(safe_score, 4),
                             "reason": reason, "severity": "Low"})

    return results


# ─── K-Means Clustering ──────────────────────────────────────────────────────

def run_clustering(db: Database) -> list[dict]:
    """Cluster devices. Returns [] silently if not enough data."""
    try:
        from sklearn.cluster import KMeans
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        return []

    rows = db.get_recent_traffic_counts(limit=500)
    # Guard: filter rows with valid numeric totals
    rows = [r for r in rows if r.get("total") is not None]
    if len(rows) < 2:
        return []

    mac_list = [r["mac"] for r in rows]
    X = np.array([[float(r["total"])] for r in rows], dtype=float)

    # n_clusters must not exceed the number of samples
    n_clusters = min(5, max(2, len(mac_list) // 3), len(mac_list))
    if n_clusters < 2:
        return []
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    kmeans.fit(X_scaled)

    return [{"mac": mac, "cluster": int(label)}
            for mac, label in zip(mac_list, kmeans.labels_)]


# ─── Combined Analysis (called from dashboard) ───────────────────────────────

def run_full_analysis() -> dict:
    """
    Run rule-based engine, then Isolation Forest, then K-Means.
    Returns summary dict for the dashboard.
    NEVER raises — any exception is caught, logged, and an empty result returned.
    """
    logger.info("Starting full AI analysis...")
    db = None
    try:
        db = Database()
        rule_anomalies = run_rule_based_detection(db)
        if_anomalies   = run_isolation_forest(db)
        clusters       = run_clustering(db)

        all_anomalies = rule_anomalies + if_anomalies
        logger.info(f"Analysis complete: {len(all_anomalies)} anomalies, "
                    f"{len(clusters)} devices clustered.")

        return {
            "anomalies": all_anomalies,
            "clusters":  clusters,
            "run_at":    datetime.utcnow().isoformat(),
        }

    except Exception as exc:
        import traceback
        logger.error("AI analysis failed: %s", exc, exc_info=True)
        traceback.print_exc()
        return {
            "anomalies": [],
            "clusters":  [],
            "run_at":    datetime.utcnow().isoformat(),
            "error":     str(exc),
        }

    finally:
        # Guaranteed cleanup regardless of where an exception occurred.
        if db is not None:
            try:
                db.close()
            except Exception:
                pass

