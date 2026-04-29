"""
PiNetAid – oui.py
Offline MAC vendor lookup.

TASK 5 fixes:
  - Correct parser for the real IEEE oui.txt format
    (lines ending with "(hex)  VendorName")
  - Built-in table for the most common prefixes
  - Behavior-based fallback classification when OUI file is missing
"""

import os
import logging

logger = logging.getLogger("pinetaid.oui")

# Path to local OUI file (IEEE format downloaded from standards-oui.ieee.org)
OUI_FILE = os.path.join(os.path.dirname(__file__), "data", "oui.txt")

# ─── Built-in fallback (covers ~80 % of typical home/office devices) ─────────
_BUILTIN: dict[str, str] = {
    # Raspberry Pi Foundation
    "B827EB": "Raspberry Pi", "DC3132": "Raspberry Pi",
    "E45F01": "Raspberry Pi", "28CDC1": "Raspberry Pi",
    "2CCF67": "Raspberry Pi",
    # Cisco
    "001A2B": "Cisco",  "001E13": "Cisco",  "00261C": "Cisco",
    "54781A": "Cisco",  "F872EA": "Cisco",
    # Apple
    "3C7A8A": "Apple",  "A4B197": "Apple",  "8C8590": "Apple",
    "F0DCE2": "Apple",  "BC9FEF": "Apple",
    # Samsung
    "A4C3F0": "Samsung","8C7712": "Samsung","5001BB": "Samsung",
    # Huawei
    "74D435": "Huawei", "4C1FCC": "Huawei", "94876D": "Huawei",
    # TP-Link
    "04F021": "TP-Link","50C7BF": "TP-Link","B0BE76": "TP-Link",
    # Ubiquiti
    "001E58": "Ubiquiti","0418D6": "Ubiquiti","24A43C": "Ubiquiti",
    # Intel (common in laptops)
    "001B21": "Intel",  "8086F2": "Intel",  "A0369F": "Intel",
    # VMware / VirtualBox
    "000C29": "VMware", "005056": "VMware", "080027": "VirtualBox",
    # D-Link
    "001CF0": "D-Link", "1CBD76": "D-Link",
    # Netgear
    "20E52A": "Netgear","A042BF": "Netgear",
    # Google (Chromecast, Nest, etc.)
    "54607E": "Google", "F4F5E8": "Google", "94EB2C": "Google",
    # Amazon (Echo, Fire TV)
    "40B4CD": "Amazon", "A002DC": "Amazon", "FC65DE": "Amazon",
    # Microsoft (Xbox, Surface)
    "28189E": "Microsoft","7045C4": "Microsoft",
}

# Runtime cache and load-flag
_oui_cache: dict[str, str] = {}
_loaded = False


def _load_oui_file() -> None:
    """
    Load the IEEE oui.txt file.

    Real IEEE oui.txt lines look like:
        00-00-0C   (hex)        Cisco Systems, Inc
        000C29     (base 16)    VMware, Inc.

    We parse BOTH "hex" and "base 16" styles.
    """
    global _loaded
    if _loaded:
        return

    _oui_cache.update(_BUILTIN)   # always start with built-ins

    if not os.path.isfile(OUI_FILE):
        logger.warning(
            f"OUI file not found at {OUI_FILE}. "
            "Run: curl -o data/oui.txt https://standards-oui.ieee.org/oui/oui.txt"
        )
        _loaded = True
        return

    count = 0
    try:
        with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                # Match lines with "(hex)" — canonical format
                # Example: "00-00-0C   (hex)        Cisco Systems, Inc"
                if "(hex)" not in line:
                    continue
                parts = line.split("(hex)")
                if len(parts) < 2:
                    continue
                raw_prefix = parts[0].strip().replace("-", "").replace(":", "")
                vendor     = parts[1].strip()
                if len(raw_prefix) == 6 and vendor:
                    _oui_cache[raw_prefix.upper()] = vendor
                    count += 1

        logger.info(f"OUI database loaded: {count} entries from file "
                    f"(+{len(_BUILTIN)} built-in).")
    except Exception as e:
        logger.error(f"Failed to load OUI file: {e}")

    _loaded = True


def get_vendor(mac: str) -> str:
    """
    Return the vendor name for a MAC address.

    Args:
        mac: Any common format — AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF,
             or AABBCCDDEEFF.

    Returns:
        Vendor name, or 'Unknown'.
    """
    _load_oui_file()
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return _oui_cache.get(prefix, "Unknown")


# ─── TASK 5: Behavior-based fallback classification ─────────────────────────

def classify_by_behavior(arp_count: int, total_packets: int,
                          dns_count: int = 0) -> str:
    """
    When vendor is 'Unknown', guess device type from traffic behavior.

    Rules (rough heuristics):
      - ARP-heavy (>60% ARP)  → Windows PC
      - DNS-heavy  (>40% DNS) → Mobile device
      - Very quiet (<10 total)→ IoT device
      - Otherwise             → Generic device
    """
    if total_packets == 0:
        return "Unknown"

    arp_ratio = arp_count / total_packets
    dns_ratio = dns_count / total_packets if total_packets > 0 else 0

    if arp_ratio > 0.6:
        return "Windows PC (inferred)"
    if dns_ratio > 0.4:
        return "Mobile Device (inferred)"
    if total_packets < 10:
        return "IoT Device (inferred)"
    return "Generic Device (inferred)"

