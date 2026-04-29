"""
PiNetAid – wifi_provision.py
============================
All WiFi provisioning logic lives here, isolated from the main dashboard.

Responsibilities:
  - Scan for nearby WiFi networks
  - Write wpa_supplicant.conf safely
  - Stop hotspot services (hostapd, dnsmasq)
  - Trigger wpa_supplicant reconnect
  - Verify IP assignment
  - Revert to hotspot mode on failure

None of these functions touch the database, AI, or capture subsystems.
All subprocess calls are wrapped in try/except — this module never raises.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import time
from typing import Optional

logger = logging.getLogger("pinetaid.wifi")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WPA_CONF_PATH  = "/etc/wpa_supplicant/wpa_supplicant.conf"
WPA_CONF_BAK   = "/etc/wpa_supplicant/wpa_supplicant.conf.bak"
WLAN_INTERFACE = "wlan0"
COUNTRY_CODE   = "SA"       # ISO-3166 country — change if needed
CONNECT_WAIT   = 8          # seconds to wait after reconfigure before checking IP
CONNECT_RETRIES = 2         # how many times to poll for IP before giving up
RETRY_INTERVAL  = 3         # seconds between IP polls


# ---------------------------------------------------------------------------
# WiFi scan
# ---------------------------------------------------------------------------

def scan_networks(interface: str = WLAN_INTERFACE) -> list[str]:
    """
    Scan for nearby WiFi SSIDs using the system 'iw' tool.

    Returns a deduplicated, sorted list of visible SSID strings.
    Returns an empty list on any error — never raises.

    Requires: iw (apt-get install iw)
    Must be run as root (or via sudo) for scan to succeed.
    """
    ssids: list[str] = []

    # Try primary scan method: iw dev wlan0 scan
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "scan"],
            capture_output=True, text=True, timeout=15,
        )
        raw = result.stdout

        # Extract SSID lines: "SSID: MyNetwork" or "\tSSID: MyNetwork"
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.startswith("SSID:"):
                ssid = stripped[len("SSID:"):].strip()
                # Skip empty / hidden SSIDs
                if ssid:
                    ssids.append(ssid)

        if ssids:
            logger.info("iw scan found %d network(s) on %s", len(set(ssids)), interface)
            return sorted(set(ssids))

    except subprocess.TimeoutExpired:
        logger.warning("iw scan timed out on %s", interface)
    except FileNotFoundError:
        logger.warning("'iw' not found — falling back to iwlist")
    except Exception as exc:
        logger.warning("iw scan failed: %s", exc)

    # Fallback: iwlist scan (older tool, always installed)
    try:
        result = subprocess.run(
            ["iwlist", interface, "scan"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            m = re.search(r'ESSID:"([^"]*)"', line)
            if m and m.group(1):
                ssids.append(m.group(1))

        logger.info("iwlist scan found %d network(s)", len(set(ssids)))
        return sorted(set(ssids))

    except Exception as exc:
        logger.warning("iwlist scan also failed: %s", exc)

    return []


# ---------------------------------------------------------------------------
# wpa_supplicant.conf writer
# ---------------------------------------------------------------------------

def _build_wpa_conf(ssid: str, password: str) -> str:
    """Return the wpa_supplicant.conf content for a single WPA2 network."""
    # Escape any double-quotes in SSID or password
    ssid_safe = ssid.replace("\\", "\\\\").replace('"', '\\"')
    pwd_safe  = password.replace("\\", "\\\\").replace('"', '\\"')
    return (
        "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n"
        "update_config=1\n"
        f"country={COUNTRY_CODE}\n"
        "\n"
        "network={\n"
        f'    ssid="{ssid_safe}"\n'
        f'    psk="{pwd_safe}"\n'
        "    key_mgmt=WPA-PSK\n"
        "}\n"
    )


def write_wpa_config(ssid: str, password: str) -> tuple[bool, str]:
    """
    Atomically overwrite /etc/wpa_supplicant/wpa_supplicant.conf.

    Steps:
      1. Back up existing config (so we can restore on failure)
      2. Write to a temp file in the same directory
      3. os.replace() — atomic on Linux (same filesystem)

    Returns (success: bool, message: str).
    """
    if not ssid:
        return False, "SSID cannot be empty"

    conf_content = _build_wpa_conf(ssid, password)
    conf_dir = os.path.dirname(WPA_CONF_PATH)

    try:
        # Backup current config
        if os.path.exists(WPA_CONF_PATH):
            subprocess.run(["cp", WPA_CONF_PATH, WPA_CONF_BAK],
                           check=False, timeout=3)

        # Write to temp file then atomically rename
        fd, tmp_path = tempfile.mkstemp(dir=conf_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(conf_content)
            os.chmod(tmp_path, 0o600)   # wpa_supplicant requires restrictive perms
            os.replace(tmp_path, WPA_CONF_PATH)
        except Exception:
            # Clean up temp file if rename failed
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        logger.info("Wrote wpa_supplicant.conf for SSID '%s'", ssid)
        return True, "Config written"

    except PermissionError:
        msg = (
            "Permission denied writing wpa_supplicant.conf. "
            "PiNetAid must run as root or with sudo for WiFi provisioning."
        )
        logger.error(msg)
        return False, msg
    except Exception as exc:
        msg = f"Failed to write wpa_supplicant.conf: {exc}"
        logger.error(msg)
        return False, msg


def restore_wpa_backup() -> bool:
    """Restore the backed-up wpa_supplicant.conf (used on connect failure)."""
    if os.path.exists(WPA_CONF_BAK):
        try:
            os.replace(WPA_CONF_BAK, WPA_CONF_PATH)
            logger.info("Restored wpa_supplicant.conf from backup")
            return True
        except Exception as exc:
            logger.warning("Could not restore wpa_supplicant backup: %s", exc)
    return False


# ---------------------------------------------------------------------------
# Service control
# ---------------------------------------------------------------------------

def _run_cmd(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """Run a shell command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as exc:
        return -1, "", str(exc)


def stop_hotspot() -> tuple[bool, str]:
    """
    Stop hostapd and dnsmasq (the hotspot services).
    Returns (success, message). Success = both stopped or were already stopped.
    """
    errors = []
    for service in ("hostapd", "dnsmasq"):
        rc, _, err = _run_cmd(["systemctl", "stop", service])
        if rc not in (0, 1, 5):  # 5 = unit not found (not installed) — OK
            errors.append(f"{service}: {err or f'exit {rc}'}")
            logger.warning("Failed to stop %s: %s", service, err)
        else:
            logger.info("Stopped service: %s", service)

    if errors:
        return False, "Could not stop: " + "; ".join(errors)
    return True, "Hotspot services stopped"


def restart_hotspot() -> tuple[bool, str]:
    """Re-enable hotspot on connect failure (best-effort recovery)."""
    for service in ("dnsmasq", "hostapd"):
        rc, _, err = _run_cmd(["systemctl", "start", service])
        if rc not in (0, 5):
            logger.warning("Failed to restart %s: %s", service, err)
    return True, "Hotspot restart attempted"


def trigger_wpa_reconfigure(interface: str = WLAN_INTERFACE) -> tuple[bool, str]:
    """
    Tell wpa_supplicant to reload its config and attempt to associate.
    Tries wpa_cli first; falls back to restarting wpa_supplicant.service,
    then dhcpcd as a last resort.
    """
    # Method 1: wpa_cli reconfigure (fastest, most reliable)
    rc, out, err = _run_cmd(["wpa_cli", "-i", interface, "reconfigure"])
    if rc == 0 and "OK" in out:
        logger.info("wpa_cli reconfigure OK on %s", interface)
        return True, "wpa_cli reconfigure OK"

    logger.warning("wpa_cli reconfigure failed (%s), trying wpa_supplicant restart", err)

    # Method 2: restart wpa_supplicant service
    rc2, _, err2 = _run_cmd(["systemctl", "restart", "wpa_supplicant"])
    if rc2 == 0:
        logger.info("wpa_supplicant.service restarted")
        return True, "wpa_supplicant restarted"

    logger.warning("wpa_supplicant restart failed (%s), trying dhcpcd", err2)

    # Method 3: restart dhcpcd (triggers wpa_supplicant on Pi OS)
    rc3, _, err3 = _run_cmd(["systemctl", "restart", "dhcpcd"])
    if rc3 == 0:
        logger.info("dhcpcd restarted")
        return True, "dhcpcd restarted"

    return False, f"All reconfigure methods failed: {err3}"


# ---------------------------------------------------------------------------
# IP verification
# ---------------------------------------------------------------------------

def get_wlan_ip(interface: str = WLAN_INTERFACE) -> Optional[str]:
    """
    Return the current IPv4 address of wlan0, or None if not connected.
    Uses 'ip addr' (preferred) with fallback to 'hostname -I'.
    """
    # Primary: ip addr show wlan0
    rc, out, _ = _run_cmd(["ip", "addr", "show", interface])
    if rc == 0:
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", out)
        if m:
            ip = m.group(1)
            # Exclude link-local addresses (169.254.x.x = no real DHCP)
            if not ip.startswith("169.254."):
                return ip

    # Fallback: hostname -I
    rc2, out2, _ = _run_cmd(["hostname", "-I"])
    if rc2 == 0:
        for token in out2.split():
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", token):
                if not token.startswith("169.254."):
                    return token

    return None


def wait_for_ip(
    interface: str = WLAN_INTERFACE,
    wait_secs: int = CONNECT_WAIT,
    retries: int = CONNECT_RETRIES,
    retry_interval: int = RETRY_INTERVAL,
) -> Optional[str]:
    """
    Wait up to (wait_secs + retries * retry_interval) seconds for an IP.
    Returns the IP string on success, None on failure.
    """
    logger.info("Waiting %ds for DHCP on %s...", wait_secs, interface)
    time.sleep(wait_secs)

    for attempt in range(retries + 1):
        ip = get_wlan_ip(interface)
        if ip:
            logger.info("Got IP %s on %s (attempt %d)", ip, interface, attempt + 1)
            return ip
        if attempt < retries:
            logger.info("No IP yet, retrying in %ds...", retry_interval)
            time.sleep(retry_interval)

    logger.warning("No IP assigned on %s after waiting", interface)
    return None


# ---------------------------------------------------------------------------
# High-level connect flow
# ---------------------------------------------------------------------------

def connect_to_wifi(ssid: str, password: str) -> dict:
    """
    Full provisioning flow.  Returns a result dict:

        {
            "success": True | False,
            "ip":      "192.168.1.x"  (only if success),
            "step":    "which step succeeded or failed",
            "message": "human-readable detail"
        }

    This function is designed to be called from a Flask route.
    It NEVER raises — all errors are returned as structured dicts.
    """
    def fail(step: str, message: str) -> dict:
        logger.error("WiFi connect FAILED at [%s]: %s", step, message)
        return {"success": False, "step": step, "message": message}

    # ── Step 1: validate inputs ───────────────────────────────────────────
    ssid     = (ssid or "").strip()
    password = password or ""
    if not ssid:
        return fail("validate", "SSID cannot be empty")

    # ── Step 2: write wpa_supplicant.conf ────────────────────────────────
    ok, msg = write_wpa_config(ssid, password)
    if not ok:
        return fail("write_config", msg)

    # ── Step 3: stop hotspot services ────────────────────────────────────
    ok, msg = stop_hotspot()
    if not ok:
        # Non-fatal: hotspot may not be installed; continue
        logger.warning("stop_hotspot: %s (continuing anyway)", msg)

    # ── Step 4: trigger wpa_supplicant reconfigure ────────────────────────
    ok, msg = trigger_wpa_reconfigure()
    if not ok:
        restore_wpa_backup()
        restart_hotspot()
        return fail("reconfigure", msg)

    # ── Step 5: wait for IP ───────────────────────────────────────────────
    ip = wait_for_ip()
    if not ip:
        restore_wpa_backup()
        trigger_wpa_reconfigure()   # re-associate with old config
        restart_hotspot()
        return fail(
            "verify_ip",
            f"Connected to '{ssid}' but did not receive an IP address. "
            "Check the WiFi password and router availability."
        )

    logger.info("WiFi provisioning successful: %s -> %s", ssid, ip)
    return {
        "success": True,
        "ip":      ip,
        "step":    "done",
        "message": f"Connected to '{ssid}'. Dashboard available at http://{ip}:5000",
    }
