"""
PiNetAid – capture.py
Passive packet capture: ARP, DHCP, and broadcast traffic.
No active scanning. Sniff only.
"""

import threading
import logging
import socket
from datetime import datetime
from ipaddress import ip_network
from scapy.all import sniff, ARP, DHCP, BOOTP, Ether

from database import Database
from oui import get_vendor

# TASK 4: keyword maps for classifying vendor names into device types.
# Applied when get_vendor() returns 'Unknown' or a generic/empty string.
_VENDOR_TYPE_MAP = [
    # Network devices (check first — routers/APs are the most distinct)
    (["cisco", "ubiquiti", "netgear", "tp-link", "d-link", "zyxel",
      "mikrotik", "juniper", "aruba", "fortinet", "linksys", "unifi"],
     "Network Device"),
    # IoT / embedded
    (["raspberry", "arduino", "espressif", "esp8266", "esp32", "shelly",
      "tuya", "sonos", "ring", "nest", "wemo", "philips hue", "lifx",
      "broadlink", "tasmota", "ewelink", "particle"],
     "IoT Device"),
    # Mobile / phones / tablets
    (["apple", "samsung", "oneplus", "huawei", "oppo", "vivo", "xiaomi",
      "realme", "nothing", "google pixel", "motorola", "nokia", "lg ",
      "zte", "alcatel"],
     "Mobile Device"),
    # PCs / laptops / workstations
    (["intel", "dell", "hp ", "lenovo", "asus", "acer", "microsoft",
      "msi ", "gigabyte", "asrock", "supermicro", "toshiba", "fujitsu"],
     "PC / Laptop"),
]


def _classify_vendor(vendor: str) -> str:
    """
    TASK 4: Return a meaningful device-type string when vendor is weak.
    Checks the raw vendor string against known keyword lists.
    Returns the vendor unchanged if it's already informative.
    """
    if not vendor or vendor.lower() in ("unknown", ""):
        return "Unknown Device"
    v = vendor.lower()
    for keywords, label in _VENDOR_TYPE_MAP:
        if any(k in v for k in keywords):
            return f"{vendor} ({label})"
    return vendor

logger = logging.getLogger("pinetaid.capture")


def get_local_macs() -> set[str]:
    """
    T2: Return the set of MAC addresses belonging to THIS device.
    Used by the AI engine to skip the Pi's own traffic.
    Reads from /sys/class/net — no extra packages needed.
    Falls back to uuid.getnode() as a secondary source.
    """
    macs: set[str] = set()
    import os
    try:
        for iface in os.listdir("/sys/class/net"):
            addr_file = f"/sys/class/net/{iface}/address"
            if os.path.exists(addr_file):
                with open(addr_file) as f:
                    mac = f.read().strip().upper()
                    if mac and mac != "00:00:00:00:00:00":
                        macs.add(mac)
    except Exception:
        pass
    # Secondary: uuid.getnode() returns the MAC as an integer
    try:
        import uuid
        raw = uuid.getnode()
        mac = ":".join(f"{(raw >> (i * 8)) & 0xFF:02X}" for i in reversed(range(6)))
        macs.add(mac)
    except Exception:
        pass
    return macs

# ─── Shared device registry (in-memory cache) ───────────────────────────────
_device_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()


def _update_device(ip: str, mac: str, packet_type: str = "ARP") -> None:
    """Update in-memory cache and persist to database."""
    mac = mac.upper()
    vendor = _classify_vendor(get_vendor(mac))  # TASK 4: enrich weak vendor names
    now = datetime.utcnow().isoformat()

    # TASK 1: derive /24 subnet from IP (e.g. "192.168.1.10" → "192.168.1.0/24")
    subnet = ""
    try:
        if ip and ip != "unknown":
            subnet = str(ip_network(f"{ip}/24", strict=False))
    except ValueError:
        pass

    with _cache_lock:
        _device_cache[mac] = {
            "ip": ip, "mac": mac, "vendor": vendor,
            "subnet": subnet, "last_seen": now,
        }

    db = Database()
    db.upsert_device(ip=ip, mac=mac, vendor=vendor, last_seen=now, subnet=subnet)
    # TASK 5: increment running packet counter so Top Active is always populated
    db.increment_packet_count(mac=mac, packet_type=packet_type)
    db.close()
    logger.info(f"Device seen: {ip} / {mac} ({vendor}) [{subnet}]")


# ─── Packet handlers ─────────────────────────────────────────────────────────

def _handle_arp(packet) -> None:
    """Extract IP/MAC from ARP request or reply."""
    arp = packet[ARP]
    if arp.psrc and arp.psrc != "0.0.0.0":
        # TASK 5: label as ARP so the counter knows the packet type
        _update_device(ip=arp.psrc, mac=arp.hwsrc, packet_type="ARP")


def _handle_dhcp(packet) -> None:
    """Extract IP/MAC from DHCP Discover or Request."""
    bootp = packet[BOOTP]
    mac_bytes = bootp.chaddr[:6]
    mac = ":".join(f"{b:02X}" for b in mac_bytes)
    ip = bootp.ciaddr if bootp.ciaddr != "0.0.0.0" else "unknown"
    if mac != "00:00:00:00:00:00":
        # TASK 5: label as DHCP
        _update_device(ip=ip, mac=mac, packet_type="DHCP")


def process_packet(packet) -> None:
    """Router: dispatch packet to the appropriate handler."""
    try:
        if packet.haslayer(ARP):
            _handle_arp(packet)
        elif packet.haslayer(DHCP) and packet.haslayer(BOOTP):
            _handle_dhcp(packet)
    except Exception as e:
        logger.warning(f"Packet processing error: {e}")


# ─── Public API ──────────────────────────────────────────────────────────────

def get_cached_devices() -> list[dict]:
    """Return a snapshot of the in-memory device cache."""
    with _cache_lock:
        return list(_device_cache.values())


class PacketCapture:
    """
    Wraps Scapy sniff() in a thread with a reliable _running flag.
    The _running flag is the single source of truth for is_running().
    stop() sets it False, wakes Scapy via a UDP loopback packet,
    joins the thread, and guarantees the caller sees is_running()==False
    before returning.
    """

    def __init__(self):
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def is_running(self) -> bool:
        """True only while the capture thread is alive."""
        return self._running and (self._thread is not None and self._thread.is_alive())

    def start(self, interface: str = None) -> bool:
        """
        Start capture. Returns False if already running.
        Sets _running = True BEFORE the thread starts so is_running()
        is correct the moment start() returns.
        """
        if self.is_running():
            logger.warning("Capture already running — ignoring start().")
            return False

        self._stop_event.clear()
        self._running = True

        self._thread = threading.Thread(
            target=self._run,
            args=(interface,),
            daemon=True,
            name="pinetaid-capture",
        )
        self._thread.start()
        logger.info(f"Capture started on interface: {interface or 'default'}")
        return True

    def stop(self) -> None:
        """
        Signal stop, wake Scapy, join the thread, then mark _running False.
        After stop() returns, is_running() is guaranteed to be False.
        """
        if not self._running:
            return

        # 1. Signal the stop event so stop_filter returns True
        self._stop_event.set()

        # 2. Wake Scapy immediately: send a tiny UDP packet to loopback.
        #    Scapy's packet loop wakes, calls stop_filter, and exits.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"\x00", ("127.0.0.1", 9))
        except Exception:
            pass

        # 3. Wait for the thread to actually finish (≤ 2 s)
        if self._thread is not None:
            self._thread.join(timeout=2.0)

        # 4. Clear state — is_running() returns False from this point on
        self._running = False
        self._thread  = None
        self._stop_event.clear()
        logger.info("Capture stopped.")

    def _run(self, interface: str = None) -> None:
        """Thread target — runs Scapy sniff() until stop_event is set."""
        def should_stop(pkt) -> bool:
            return self._stop_event.is_set()

        try:
            sniff(
                iface=interface,
                filter="arp or (udp and (port 67 or port 68))",
                prn=process_packet,
                store=False,
                stop_filter=should_stop,
            )
        except Exception as exc:
            logger.error(f"Capture error: {exc}")
        finally:
            # Ensure _running reflects reality even if sniff() raises
            self._running = False
            logger.info("Capture thread exited.")


# Module-level singleton used by dashboard.py
_capture = PacketCapture()


def start_capture_thread(interface: str = None) -> bool:
    """Start the module-level PacketCapture singleton. Returns False if already running."""
    return _capture.start(interface=interface)


def stop_capture_thread() -> None:
    """Stop the module-level PacketCapture singleton."""
    _capture.stop()


def capture_is_running() -> bool:
    """Return True if the module-level capture is active."""
    return _capture.is_running()

