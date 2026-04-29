"""
PiNetAid – diagnostics.py
Network diagnostics: ping, DNS lookup, gateway reachability.
All operations are subprocess-based; no raw sockets needed.
"""

import subprocess
import socket
import logging
import shlex

logger = logging.getLogger("pinetaid.diagnostics")

# ─── Ping ─────────────────────────────────────────────────────────────────────

def ping(host: str, count: int = 4, timeout: int = 2) -> dict:
    """
    ICMP ping a host.

    Args:
        host:    IP address or hostname.
        count:   Number of packets.
        timeout: Per-packet timeout in seconds.

    Returns:
        {
          "host": str,
          "reachable": bool,
          "packets_sent": int,
          "packets_received": int,
          "packet_loss_pct": float,
          "avg_rtt_ms": float | None,
          "output": str
        }
    """
    # Sanitise host to prevent shell injection
    safe_host = shlex.quote(host)
    cmd = ["ping", "-c", str(count), "-W", str(timeout), host]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=count * timeout + 5,
        )
        output = result.stdout + result.stderr
        reachable = result.returncode == 0

        # Parse summary line: "4 packets transmitted, 3 received, 25% packet loss"
        packets_sent = count
        packets_received = 0
        loss_pct = 100.0
        avg_rtt = None

        for line in output.splitlines():
            if "packets transmitted" in line:
                parts = line.split(",")
                packets_sent = int(parts[0].split()[0])
                packets_received = int(parts[1].split()[0])
                loss_pct = float(parts[2].split("%")[0].split()[-1])
            if "rtt min/avg/max" in line or "round-trip" in line:
                # rtt min/avg/max/mdev = 1.2/2.3/3.4/0.5 ms
                stats = line.split("=")[-1].strip().split("/")
                avg_rtt = float(stats[1]) if len(stats) >= 2 else None

        return {
            "host": host,
            "reachable": reachable,
            "packets_sent": packets_sent,
            "packets_received": packets_received,
            "packet_loss_pct": loss_pct,
            "avg_rtt_ms": avg_rtt,
            "output": output.strip(),
        }

    except subprocess.TimeoutExpired:
        return {
            "host": host,
            "reachable": False,
            "packets_sent": count,
            "packets_received": 0,
            "packet_loss_pct": 100.0,
            "avg_rtt_ms": None,
            "output": "Timed out",
        }
    except Exception as e:
        logger.error(f"Ping error for {host}: {e}")
        return {
            "host": host,
            "reachable": False,
            "packets_sent": count,
            "packets_received": 0,
            "packet_loss_pct": 100.0,
            "avg_rtt_ms": None,
            "output": str(e),
        }


# ─── DNS Lookup ───────────────────────────────────────────────────────────────

def dns_lookup(hostname: str) -> dict:
    """
    Resolve a hostname to IP addresses (uses system resolver).

    Returns:
        {
          "hostname": str,
          "resolved": bool,
          "addresses": list[str],
          "error": str | None
        }
    """
    try:
        info = socket.getaddrinfo(hostname, None)
        addresses = list({r[4][0] for r in info})   # deduplicate
        return {
            "hostname": hostname,
            "resolved": True,
            "addresses": addresses,
            "error": None,
        }
    except socket.gaierror as e:
        return {
            "hostname": hostname,
            "resolved": False,
            "addresses": [],
            "error": str(e),
        }


# ─── Gateway Reachability ────────────────────────────────────────────────────

def get_default_gateway() -> str | None:
    """Return the default gateway IP from the routing table."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        # Output: "default via 192.168.1.1 dev eth0 ..."
        for line in result.stdout.splitlines():
            if "default via" in line:
                return line.split("via")[1].split()[0]
    except Exception as e:
        logger.warning(f"Could not determine gateway: {e}")
    return None


def check_gateway() -> dict:
    """Ping the default gateway and return results."""
    gw = get_default_gateway()
    if not gw:
        return {"gateway": None, "reachable": False, "error": "Could not determine gateway"}
    result = ping(gw, count=2)
    result["gateway"] = gw
    return result


# ─── Port Check ──────────────────────────────────────────────────────────────

def check_port(host: str, port: int, timeout: int = 2) -> dict:
    """
    TCP port reachability check.

    Returns:
        {"host": str, "port": int, "open": bool, "error": str | None}
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"host": host, "port": port, "open": True, "error": None}
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"host": host, "port": port, "open": False, "error": str(e)}
