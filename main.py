"""
PiNetAid – main.py
Application entry point: starts capture thread + dashboard.
"""

import argparse
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("pinetaid.log"),
    ]
)

logger = logging.getLogger("pinetaid")


def parse_args():
    parser = argparse.ArgumentParser(description="PiNetAid – Offline Network Monitor")
    parser.add_argument("--interface", "-i", default=None,
                        help="Network interface to capture on (default: auto)")
    parser.add_argument("--port", "-p", type=int, default=5000,
                        help="Dashboard HTTP port (default: 5000)")
    parser.add_argument("--no-capture", action="store_true",
                        help="Start dashboard only, no packet capture")
    parser.add_argument("--debug", action="store_true",
                        help="Enable Flask debug mode")
    return parser.parse_args()


# True while /api/wifi/connect is in progress — watchdog skips during this window
provisioning_active = False


def _init_network_mode() -> None:
    """
    Set the initial network mode once at startup.
    Respects the force-hotspot flag left from a previous setup session.
    Non-fatal — failures are logged and the dashboard still starts.
    """
    try:
        from wifi_provision import (get_wlan_ip, start_hotspot, stop_hotspot,
                                    is_force_hotspot_enabled, setup_mdns,
                                    _nm_release_wlan0, WLAN_INTERFACE)
        setup_mdns()
        _nm_release_wlan0(WLAN_INTERFACE)   # ensure NM leaves wlan0 alone at boot

        if is_force_hotspot_enabled():
            logger.info("Force-hotspot flag found — starting hotspot.")
            start_hotspot()
            return

        ip = get_wlan_ip()
        if ip:
            logger.info("WiFi connected (%s) — stopping hotspot if running.", ip)
            stop_hotspot()
        else:
            logger.info("No WiFi IP at boot — starting hotspot (AP mode).")
            result = start_hotspot()
            if result.get("success"):
                logger.info("Hotspot ready at http://%s:5000/wifi-setup",
                            result.get("hotspot_ip", "192.168.4.1"))
            else:
                logger.warning("Hotspot start failed: %s", result.get("message"))
    except Exception as exc:
        logger.warning("_init_network_mode failed (dashboard still starts): %s", exc)


def _start_network_watchdog(interval: int = 30) -> None:
    """
    Daemon thread that monitors WiFi state every `interval` seconds.
    Does nothing when the forced-hotspot flag is set or during provisioning.
    """
    import threading, time as _time

    def _loop() -> None:
        try:
            from wifi_provision import (get_wlan_ip, is_hotspot_active,
                                        is_force_hotspot_enabled,
                                        start_hotspot, stop_hotspot)
        except Exception as exc:
            logger.warning("Watchdog import failed: %s", exc)
            return

        while True:
            _time.sleep(interval)
            try:
                if provisioning_active or is_force_hotspot_enabled():
                    continue   # never touch the interface during setup mode or connect

                ip         = get_wlan_ip()
                ap_running = is_hotspot_active()

                if not ip and not ap_running:
                    logger.info("Watchdog: WiFi lost — starting hotspot.")
                    start_hotspot()
                elif ip and ap_running:
                    logger.info("Watchdog: WiFi restored (%s) — stopping hotspot.", ip)
                    stop_hotspot()
            except Exception as exc:
                logger.warning("Watchdog error (continuing): %s", exc)

    t = threading.Thread(target=_loop, name="net-watchdog", daemon=True)
    t.start()
    logger.info("Network watchdog started (interval: %ds).", interval)


def main():
    args = parse_args()

    # Ensure data directory exists
    os.makedirs("data", exist_ok=True)

    logger.info("=" * 50)
    logger.info("PiNetAid starting")
    logger.info(f"  Interface : {args.interface or 'auto'}")
    logger.info(f"  Dashboard : http://0.0.0.0:{args.port}")
    logger.info(f"  Capture   : {'disabled' if args.no_capture else 'enabled'}")
    logger.info("=" * 50)

    # Set initial network mode before the dashboard opens any ports
    _init_network_mode()

    # Background thread that recovers hotspot if WiFi drops
    _start_network_watchdog(interval=30)

    # Import dashboard after capture so global state is initialised
    import dashboard as dash

    try:
        dash.run_dashboard(port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        logger.info("Shutdown requested.")

    logger.info("PiNetAid stopped.")


if __name__ == "__main__":
    main()
