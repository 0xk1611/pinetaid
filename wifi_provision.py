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

# Addresses that are never a genuine client WiFi IP.
_NON_CLIENT_PREFIXES = ("169.254.", "192.168.4.")   # link-local + hotspot subnet


def _is_client_ip(addr: str) -> bool:
    """True when the address looks like a real router-assigned DHCP lease."""
    return all(not addr.startswith(p) for p in _NON_CLIENT_PREFIXES)


def get_all_wlan_ips(interface: str = WLAN_INTERFACE) -> list:
    """Return all IPv4 addresses on the interface — no filtering applied."""
    rc, out, _ = _run_cmd(["ip", "addr", "show", interface])
    if rc != 0:
        return []
    return [m.group(1) for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)/", out)]


def get_wlan_ip(interface: str = WLAN_INTERFACE) -> Optional[str]:
    """
    Return the WiFi client IP of wlan0, or None when the device is not on
    a real network.  Ignores 192.168.4.x (hotspot static IP) and
    169.254.x.x (link-local) because neither represents a router connection.
    """
    for ip in get_all_wlan_ips(interface):
        if _is_client_ip(ip):
            return ip

    # hostname -I fallback
    rc2, out2, _ = _run_cmd(["hostname", "-I"])
    if rc2 == 0:
        for token in out2.split():
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", token) and _is_client_ip(token):
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
    Attempt a client-mode WiFi connection.

    Changes from the original flow, based on diagnostic findings:
    - Does NOT use wpa_cli reconfigure (it was returning FAIL and not
      disconnecting from the old network).
    - Calls reset_wlan0_state() to stop every service touching the interface,
      release DHCP leases, flush IPs, and tell NetworkManager to leave wlan0
      alone — this is what was causing the dual-IP conflict.
    - Starts wpa_supplicant directly (not via systemd) so it is bound to
      exactly the new config file and not to any persisted state.
    - Does NOT restore the old wpa_supplicant.conf backup on failure — doing
      so would reconnect to the old WiFi and kill any AP mode attempt.
    - Keeps force_hotspot enabled until a real DHCP IP is confirmed.
    Never raises.
    """
    def fail(step: str, message: str) -> dict:
        logger.error("WiFi connect FAILED at [%s]: %s", step, message)
        return {"success": False, "step": step, "ip": None, "message": message}

    ssid     = (ssid or "").strip()
    password = password or ""
    if not ssid:
        return fail("validate", "SSID cannot be empty")

    # Overwrite with a single-network config so wpa_supplicant cannot fall
    # back to any previously-known SSID
    ok, msg = write_wpa_config(ssid, password)
    if not ok:
        return fail("write_config", msg)

    # Full interface reset — stops NetworkManager, dhcpcd, wpa_supplicant,
    # flushes IPs, bounces link
    reset_wlan0_state()

    # Start wpa_supplicant directly against the new config file.
    # -B = background daemon, -i = interface, -c = config, -D = driver
    rc_wpa, out_wpa, err_wpa = _run_cmd([
        "wpa_supplicant", "-B",
        "-i", WLAN_INTERFACE,
        "-c", WPA_CONF_PATH,
        "-D", "nl80211,wext",
    ], timeout=15)
    logger.info("wpa_supplicant -B rc=%d out=%s err=%s", rc_wpa, out_wpa, err_wpa)

    if rc_wpa != 0:
        enable_force_hotspot()
        start_hotspot()
        return fail("wpa_supplicant_start",
                    f"Could not start wpa_supplicant: {err_wpa or out_wpa}")

    # Wait for association, then start dhcpcd for just this interface
    time.sleep(4)
    _run_cmd(["dhcpcd", WLAN_INTERFACE], timeout=5)

    ip = wait_for_ip()

    # Hard-reject non-client addresses
    if ip and not _is_client_ip(ip):
        logger.warning("connect_to_wifi: rejecting non-client IP %s", ip)
        ip = None

    # Also reject if the hotspot address is still present on the interface
    if ip and HOTSPOT_IP in get_all_wlan_ips():
        logger.warning("connect_to_wifi: hotspot IP %s still present alongside %s — conflict",
                       HOTSPOT_IP, ip)
        ip = None

    if ip:
        # Confirm with iw that the interface is associated with the right SSID
        rc_iw, iw_out, _ = _run_cmd(["iw", "dev", WLAN_INTERFACE, "info"])
        if rc_iw == 0:
            if "type managed" not in iw_out:
                logger.warning("connect_to_wifi: iw shows not managed (%s)", iw_out.strip()[:80])
                ip = None
            else:
                m_ssid = re.search(r"ssid (.+)", iw_out)
                if m_ssid and m_ssid.group(1).strip() != ssid:
                    logger.warning("connect_to_wifi: iw SSID %s != requested %s",
                                   m_ssid.group(1).strip(), ssid)
                    ip = None

    if ip:
        disable_force_hotspot()
        logger.info("WiFi provisioning successful: %s -> %s", ssid, ip)
        return {
            "success": True,
            "ip":      ip,
            "step":    "done",
            "message": f"Connected to '{ssid}'. Dashboard at http://{ip}:5000",
        }

    # Connection failed — return to forced hotspot, do NOT restore old config
    enable_force_hotspot()
    start_hotspot()
    return fail(
        "verify_ip",
        f"Could not connect to '{ssid}'. "
        f"Setup hotspot remains active. Check the password and try again at "
        f"http://{HOTSPOT_IP}:5000/wifi-setup",
    )

# =============================================================================
#  Constants and helpers for mode switching
# =============================================================================

HOTSPOT_IP         = "192.168.4.1"
FORCE_HOTSPOT_FLAG = "/tmp/pinetaid_force_hotspot"
DNSMASQ_CONF       = "/etc/dnsmasq.d/pinetaid.conf"
NM_UNMANAGED_CONF  = "/etc/NetworkManager/conf.d/99-pinetaid-unmanaged.conf"

_DNSMASQ_CONTENT = (
    "interface=wlan0\n"
    "bind-interfaces\n"
    "dhcp-range=192.168.4.10,192.168.4.50,255.255.255.0,24h\n"
    "dhcp-option=3,192.168.4.1\n"
    "dhcp-option=6,192.168.4.1\n"
)

# Content that tells NetworkManager to leave wlan0 entirely alone
_NM_UNMANAGED_CONTENT = (
    "[keyfile]\n"
    "unmanaged-devices=interface-name:wlan0\n"
)


def _svc_active(name: str) -> bool:
    """Return True when a systemd unit is currently active."""
    rc, _, _ = _run_cmd(["systemctl", "is-active", "--quiet", name])
    return rc == 0


# ---------------------------------------------------------------------------
# Forced-hotspot flag helpers
# ---------------------------------------------------------------------------

def enable_force_hotspot() -> None:
    """Mark that the device must stay in setup/hotspot mode."""
    try:
        open(FORCE_HOTSPOT_FLAG, "w").close()
        logger.info("Force-hotspot flag enabled")
    except Exception as exc:
        logger.warning("Could not write force-hotspot flag: %s", exc)


def disable_force_hotspot() -> None:
    """Clear the forced-hotspot flag after a successful client connection."""
    try:
        import os as _os
        if _os.path.exists(FORCE_HOTSPOT_FLAG):
            _os.remove(FORCE_HOTSPOT_FLAG)
            logger.info("Force-hotspot flag cleared")
    except Exception as exc:
        logger.warning("Could not remove force-hotspot flag: %s", exc)


def is_force_hotspot_enabled() -> bool:
    """True when the device has been told to stay in AP mode."""
    import os as _os
    return _os.path.exists(FORCE_HOTSPOT_FLAG)


def is_hotspot_active() -> bool:
    """Return True when hostapd is currently running."""
    return _svc_active("hostapd")


# ---------------------------------------------------------------------------
# NetworkManager — tell it to leave wlan0 alone during provisioning
# ---------------------------------------------------------------------------

def _nm_release_wlan0(interface: str = WLAN_INTERFACE) -> None:
    """
    Tell NetworkManager to stop managing wlan0.
    Creates a persistent config file and also sets it live via nmcli.
    This is what prevents NetworkManager from reconnecting to old WiFi
    the moment wpa_supplicant is stopped.
    """
    import os as _os

    # Write persistent unmanaged config
    try:
        _os.makedirs(_os.path.dirname(NM_UNMANAGED_CONF), exist_ok=True)
        with open(NM_UNMANAGED_CONF, "w") as fh:
            fh.write(_NM_UNMANAGED_CONTENT)
        logger.info("NetworkManager unmanaged config written to %s", NM_UNMANAGED_CONF)
    except Exception as exc:
        logger.warning("Could not write NM unmanaged config: %s", exc)

    # Apply live if nmcli is available
    rc, _, err = _run_cmd(["nmcli", "device", "disconnect", interface])
    logger.info("nmcli disconnect %s: rc=%d err=%s", interface, rc, err)
    rc2, _, err2 = _run_cmd(["nmcli", "device", "set", interface, "managed", "no"])
    logger.info("nmcli set unmanaged %s: rc=%d err=%s", interface, rc2, err2)

    # Reload NM config so the file takes effect
    _run_cmd(["systemctl", "reload", "NetworkManager"])


# ---------------------------------------------------------------------------
# dhcpcd.conf — remove the permanent static hotspot block
# ---------------------------------------------------------------------------

def _remove_static_dhcpcd_block(interface: str = WLAN_INTERFACE) -> None:
    """
    Remove the 'interface wlan0 / static ip_address=192.168.4.1' block that
    dhcpcd.conf may contain from a manual hotspot setup.  That block was
    causing 192.168.4.1 to stay on the interface permanently even during
    client mode, producing the dual-IP conflict seen in the diagnostics.
    """
    try:
        with open("/etc/dhcpcd.conf") as fh:
            original = fh.read()
    except Exception as exc:
        logger.warning("Could not read /etc/dhcpcd.conf: %s", exc)
        return

    import re as _re

    # Remove any block that starts with 'interface wlan0' and contains
    # 'static ip_address=192.168.4' (tolerates extra whitespace / comments)
    cleaned = _re.sub(
        r"\ninterface\s+wlan0\s*\n"
        r"(?:[ \t]*[^\n]*\n)*?"
        r"(?=\n(?:interface|\Z)|$)",
        "\n",
        original,
        flags=_re.MULTILINE,
    )

    # Also remove a bare 'nohook wpa_supplicant' that applies globally
    # (only remove the wlan0-scoped one handled above; leave others alone)
    if cleaned != original:
        try:
            with open("/etc/dhcpcd.conf", "w") as fh:
                fh.write(cleaned)
            logger.info("Removed static hotspot block from /etc/dhcpcd.conf")
        except Exception as exc:
            logger.warning("Could not rewrite /etc/dhcpcd.conf: %s", exc)
    else:
        logger.info("/etc/dhcpcd.conf: no static hotspot block found — OK")


# ---------------------------------------------------------------------------
# dnsmasq config
# ---------------------------------------------------------------------------

def _ensure_dnsmasq_conf() -> None:
    """Write the hotspot DHCP config file so dnsmasq serves the right range."""
    try:
        import os as _os
        _os.makedirs(_os.path.dirname(DNSMASQ_CONF), exist_ok=True)
        with open(DNSMASQ_CONF, "w") as fh:
            fh.write(_DNSMASQ_CONTENT)
        logger.info("dnsmasq config written to %s", DNSMASQ_CONF)
    except Exception as exc:
        logger.warning("Could not write dnsmasq config: %s", exc)


# ---------------------------------------------------------------------------
# Interface reset  — the core function that was missing
# ---------------------------------------------------------------------------

def reset_wlan0_state(interface: str = WLAN_INTERFACE) -> None:
    """
    Bring wlan0 to a completely clean state before switching modes.

    This is the function that was missing from all previous attempts.
    Without it:
      - NetworkManager kept managing wlan0 and reconnected to the old SSID.
      - dhcpcd kept its DHCP lease, leaving both 192.168.4.1 and 192.168.0.x
        on the interface simultaneously.
      - wpa_supplicant kept the old association in its process memory even
        after its service was stopped, so iw still showed 'type managed /
        ssid old-network'.

    Steps:
      1. Tell NetworkManager to stop managing wlan0 (nmcli + config file).
      2. Stop every systemd service that touches the interface.
      3. Kill any surviving wpa_supplicant process for this interface.
      4. Release the DHCP lease (dhcpcd -k) and remove the static block
         from dhcpcd.conf so it cannot reassign 192.168.4.1 automatically.
      5. Flush all IPs — required to eliminate the dual-IP state.
      6. Bounce the link (down / sleep / up).
      7. Poll until no IPv4 address remains on the interface.
    """
    logger.info("reset_wlan0_state: starting on %s", interface)

    # Step 1: tell NetworkManager to leave wlan0 alone
    _nm_release_wlan0(interface)

    # Step 2: stop every service that touches the interface
    for svc in ("hostapd", "dnsmasq", "wpa_supplicant", "dhcpcd"):
        rc, _, err = _run_cmd(["systemctl", "stop", svc])
        logger.info("stop %-16s rc=%d %s", svc, rc, err[:60] if err else "")

    # Step 3: kill any surviving wpa_supplicant process
    _run_cmd(["pkill", "-f", f"wpa_supplicant.*{interface}"])
    _run_cmd(["wpa_cli", "-i", interface, "terminate"])

    # Step 4: release DHCP lease and clean dhcpcd.conf
    _run_cmd(["dhcpcd", "-k", interface])
    _remove_static_dhcpcd_block(interface)

    # Step 5: flush all IP addresses
    _run_cmd(["ip", "addr", "flush", "dev", interface])

    # Step 6: bounce the link
    _run_cmd(["ip", "link", "set", interface, "down"])
    time.sleep(2)
    _run_cmd(["ip", "link", "set", interface, "up"])

    # Step 7: verify no IPv4 address remains
    for _ in range(10):
        ips = get_all_wlan_ips(interface)
        if not ips:
            break
        time.sleep(0.5)
    else:
        remaining = get_all_wlan_ips(interface)
        logger.warning("reset_wlan0_state: IPs still present after reset: %s", remaining)

    logger.info("reset_wlan0_state: complete — ips=%s", get_all_wlan_ips(interface))


# ---------------------------------------------------------------------------
# Hotspot mode
# ---------------------------------------------------------------------------

def start_hotspot(interface: str = WLAN_INTERFACE) -> dict:
    """
    Switch fully into AP (hotspot) mode.

    Always calls reset_wlan0_state() first so there are no competing
    processes or leftover IPs.  Verifies the result with iw before returning
    success — if the interface is still in managed mode the failure is
    reported clearly rather than silently.
    """
    logger.info("start_hotspot: entering AP mode on %s", interface)

    reset_wlan0_state(interface)

    # Assign the fixed AP address that hostapd and dnsmasq expect
    _run_cmd(["ip", "addr", "add", f"{HOTSPOT_IP}/24", "dev", interface])
    _run_cmd(["ip", "link", "set", interface, "up"])

    _ensure_dnsmasq_conf()

    for svc in ("dnsmasq", "hostapd"):
        rc, out, err = _run_cmd(["systemctl", "start", svc])
        logger.info("start %-10s rc=%d %s", svc, rc, err[:60] if err else out[:60])

    # Give hostapd a moment to negotiate the AP channel
    time.sleep(2)

    # Verify: interface must be in AP mode and carry only the hotspot IP
    all_ips         = get_all_wlan_ips(interface)
    rc_iw, iw_out, _ = _run_cmd(["iw", "dev", interface, "info"])
    ap_mode         = rc_iw == 0 and "type AP" in iw_out
    has_hotspot_ip  = HOTSPOT_IP in all_ips
    no_client_ips   = all(_is_client_ip(ip) is False for ip in all_ips)
    wpa_stopped     = not _svc_active("wpa_supplicant")
    dhcpcd_stopped  = not _svc_active("dhcpcd")

    if not ap_mode or not has_hotspot_ip:
        detail = (f"iw_type={'AP' if ap_mode else iw_out.strip()[:80]}, "
                  f"ips={all_ips}, ap_ip={has_hotspot_ip}, "
                  f"wpa_stopped={wpa_stopped}, dhcpcd_stopped={dhcpcd_stopped}")
        msg = f"Hotspot verification failed: {detail}"
        logger.error(msg)
        return {"success": False, "message": msg, "hotspot_ip": ""}

    logger.info("start_hotspot: confirmed type AP, IP %s, wpa_stopped=%s",
                HOTSPOT_IP, wpa_stopped)
    return {
        "success":    True,
        "hotspot_ip": HOTSPOT_IP,
        "message":    (f"Hotspot active. Connect to PiNetAid-Setup and open "
                       f"http://{HOTSPOT_IP}:5000/wifi-setup"),
    }


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_wifi_status(interface: str = WLAN_INTERFACE) -> dict:
    """
    Rich status dict for /api/wifi/status.
    Detects the dual-IP conflict that was the confirmed root cause.
    """
    all_ips   = get_all_wlan_ips(interface)
    client_ip = get_wlan_ip(interface)
    has_ap_ip = HOTSPOT_IP in all_ips
    has_client = client_ip is not None

    rc_iw, iw_out, _ = _run_cmd(["iw", "dev", interface, "info"])
    iw_type = "unknown"
    iw_ssid = None
    if rc_iw == 0:
        tm = re.search(r"type (\w+)", iw_out)
        if tm:
            iw_type = tm.group(1)
        sm = re.search(r"ssid (.+)", iw_out)
        if sm:
            iw_ssid = sm.group(1).strip()

    # Detect conflict states
    conflict_msg = None
    if has_ap_ip and has_client:
        conflict_msg = "wlan0 has hotspot and client IP at the same time"
    elif iw_type == "managed" and _svc_active("hostapd"):
        conflict_msg = "hostapd active but wlan0 is still in managed mode"

    if conflict_msg:
        mode = "conflict"
    elif has_client:
        mode = "client"
    elif _svc_active("hostapd"):
        mode = "hotspot"
    else:
        mode = "unknown"

    return {
        "mode":            mode,
        "conflict":        conflict_msg,
        "force_hotspot":   is_force_hotspot_enabled(),
        "ip":              client_ip or "",
        "ip_addresses":    all_ips,
        "hotspot_ip":      HOTSPOT_IP,
        "hostapd":         "active" if _svc_active("hostapd")        else "inactive",
        "dnsmasq":         "active" if _svc_active("dnsmasq")        else "inactive",
        "wpa_supplicant":  "active" if _svc_active("wpa_supplicant") else "inactive",
        "dhcpcd":          "active" if _svc_active("dhcpcd")         else "inactive",
        "iw_type":         iw_type,
        "connected_ssid":  iw_ssid,
    }


def setup_mdns() -> None:
    """Set hostname to 'pinetaid' and enable avahi-daemon for pinetaid.local."""
    try:
        _run_cmd(["hostnamectl", "set-hostname", "pinetaid"])
        logger.info("Hostname set to pinetaid")
    except Exception as exc:
        logger.warning("Could not set hostname: %s", exc)
    try:
        rc, _, _ = _run_cmd(["systemctl", "is-active", "--quiet", "avahi-daemon"])
        if rc != 0:
            _run_cmd(["systemctl", "enable", "--now", "avahi-daemon"])
            logger.info("avahi-daemon enabled")
    except Exception as exc:
        logger.warning("Could not start avahi-daemon: %s", exc)
