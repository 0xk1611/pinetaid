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


    # Import dashboard after capture so global state is initialised
    import dashboard as dash

    try:
        dash.run_dashboard(port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        logger.info("Shutdown requested.")


    logger.info("PiNetAid stopped.")


if __name__ == "__main__":
    main()
