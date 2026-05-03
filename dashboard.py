"""
PiNetAid – dashboard.py
Flask web dashboard.

Changes in this version:
  TASK 1 – Removed ALL {% block body %} / {% endblock %} tags.
           Each route calls render_page(content) — a plain Python function.
  TASK 2 – All devices returned (no [:5] slice or LIMIT).
  TASK 3 – Device tables auto-refresh every 5 s via lightweight fetch() AJAX.
  TASK 4 – Anomaly page shows 'reason' column for every flagged device.
  TASK 6 – /top-devices, /suspicious, /device-types, /export added.
           Network Health banner on Overview.
"""

import json
import logging
import threading
from datetime import datetime

from flask import (
    Flask, render_template_string, request,
    redirect, url_for, session, jsonify, flash, Response,
    get_flashed_messages
)

from database import Database
from ai import run_full_analysis
from diagnostics import ping, dns_lookup, check_gateway
from auth import login_required, verify_user, user_exists, create_user, generate_secret_key
from capture import (
    start_capture_thread, stop_capture_thread,
    capture_is_running, get_cached_devices,
)
try:
    from wifi_provision import (
        scan_networks, connect_to_wifi, get_wifi_status,
        start_hotspot, enable_force_hotspot, HOTSPOT_IP,
    )
    _WIFI_AVAILABLE = True
except ImportError:
    _WIFI_AVAILABLE = False

logger = logging.getLogger("pinetaid.dashboard")

app = Flask(__name__)
app.secret_key = generate_secret_key()
# Capture state is now managed inside capture.PacketCapture singleton.
# Use capture_is_running(), start_capture_thread(), stop_capture_thread().


# TASK 1: detect the Pi's own /24 subnet so the dashboard can auto-filter
import socket as _socket
from ipaddress import ip_network as _ip_network

def _detect_current_subnet() -> str:
    """Return the Pi's /24 subnet (e.g. '192.168.1.0/24'), or '' on failure."""
    try:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            local_ip = s.getsockname()[0]
        return str(_ip_network(f"{local_ip}/24", strict=False))
    except Exception:
        return ""


def _get_active_interfaces() -> list[str]:
    """
    TASK 6: Return network interfaces that have an IPv4 address assigned.
    Always includes eth0 and wlan0 as fallback options even if not found.
    """
    found = []
    try:
        import subprocess
        out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"],
                                      stderr=subprocess.DEVNULL, text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                iface = parts[1]
                # Skip loopback
                if iface != "lo" and iface not in found:
                    found.append(iface)
    except Exception:
        pass
    # Always guarantee at least these two common options
    for fallback in ["eth0", "wlan0"]:
        if fallback not in found:
            found.append(fallback)
    return found

def _get_network_info() -> dict:
    """
    TASK 4: Detect default gateway and interface broadcast address.
    Uses read-only system commands — no packages needed.
    Returns dict with keys: gateway, broadcast, local_ip  (all strings, "" on failure).
    """
    import subprocess, re
    info = {"gateway": "", "broadcast": "", "local_ip": ""}

    # Detect default gateway via 'ip route'
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL, text=True, timeout=3
        )
        m = re.search(r"default via ([\d\.]+)", out)
        if m:
            info["gateway"] = m.group(1)
    except Exception:
        pass

    # Detect local IP and broadcast via 'ip addr'
    try:
        # Get the primary non-loopback interface
        ifaces = _get_active_interfaces()
        iface  = ifaces[0] if ifaces else "eth0"
        out2   = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface],
            stderr=subprocess.DEVNULL, text=True, timeout=3
        )
        m2 = re.search(r"inet ([\d\.]+)/\d+\s+brd ([\d\.]+)", out2)
        if m2:
            info["local_ip"]  = m2.group(1)
            info["broadcast"] = m2.group(2)
    except Exception:
        pass

    # Fallback for local_ip using socket trick (no packets sent)
    if not info["local_ip"]:
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as s:
                s.connect(("10.255.255.255", 1))
                info["local_ip"] = s.getsockname()[0]
        except Exception:
            pass

    return info

_CSS = """<style>
:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--green:#3fb950;
      --red:#f85149;--yellow:#d29922;--blue:#58a6ff;--text:#e6edf3;
      --muted:#8b949e;--font:'Courier New',monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;min-height:100vh}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
nav{background:var(--surface);border-bottom:1px solid var(--border);
    padding:12px 24px;display:flex;align-items:center;gap:20px}
.logo{color:var(--green);font-size:18px;font-weight:bold;letter-spacing:2px}
nav a{color:var(--muted);font-size:13px}
nav a:hover,.nav-active{color:var(--text)!important;text-decoration:none!important}
.nav-right{margin-left:auto}
.container{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:20px;margin-bottom:20px}
h2{font-size:13px;margin-bottom:12px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:6px;
      padding:20px;margin-bottom:20px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
           gap:16px;margin-bottom:24px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:16px}
.stat-label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.stat-value{font-size:26px;font-weight:bold}
.c-green{color:var(--green)}.c-red{color:var(--red)}
.c-blue{color:var(--blue)}.c-yellow{color:var(--yellow)}
table{width:100%;border-collapse:collapse}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px;
   border-bottom:1px solid var(--border);padding:8px 12px;text-align:left}
td{padding:9px 12px;border-bottom:1px solid #21262d;vertical-align:middle}
tr:hover td{background:#1c2128}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold}
.badge-ok{background:#1a3a2a;color:var(--green)}
.badge-bad{background:#3d1f1f;color:var(--red)}
.badge-type{background:#1a2a3d;color:var(--blue)}
/* Task 3: severity-level badge colours */
.sev-critical{background:#4a0f0f;color:#ff6b6b;border:1px solid #ff6b6b}
.sev-high{background:#3d1f1f;color:var(--red);border:1px solid var(--red)}
.sev-medium{background:#3d2f0f;color:var(--yellow);border:1px solid var(--yellow)}
.sev-low{background:#1a2a3d;color:var(--blue);border:1px solid var(--blue)}
.mac{color:var(--yellow);font-size:12px}.muted{color:var(--muted);font-size:12px}
.form-group{margin-bottom:16px}
label{display:block;margin-bottom:5px;color:var(--muted);font-size:12px}
input[type=text],input[type=password]{background:var(--bg);border:1px solid var(--border);
  color:var(--text);padding:8px 12px;border-radius:4px;font-family:var(--font);
  font-size:14px;width:100%;outline:none}
input:focus{border-color:var(--blue)}
.btn{padding:8px 18px;border:none;border-radius:4px;cursor:pointer;
     font-family:var(--font);font-size:13px;font-weight:bold;letter-spacing:1px}
.btn-g{background:var(--green);color:#0d1117}
.btn-s{background:var(--surface);color:var(--text);border:1px solid var(--border)}
.btn-r{background:var(--red);color:white}
.alert{padding:10px 16px;border-radius:4px;margin-bottom:14px;font-size:13px}
.al-e{background:#3d1f1f;border:1px solid var(--red);color:var(--red)}
.al-s{background:#1a3a2a;border:1px solid var(--green);color:var(--green)}
.al-i{background:#1a2a3d;border:1px solid var(--blue);color:var(--blue)}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-box{background:var(--surface);border:1px solid var(--border);
           border-radius:8px;padding:40px;width:360px}
.login-logo{text-align:center;color:var(--green);font-size:24px;font-weight:bold;
            letter-spacing:3px;margin-bottom:8px}
.login-sub{text-align:center;color:var(--muted);font-size:12px;margin-bottom:28px}
.terminal{background:#010409;border:1px solid var(--border);border-radius:4px;
          padding:16px;font-size:12px;color:var(--green);white-space:pre-wrap;
          max-height:280px;overflow-y:auto}
.sdot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.sdot-g{background:var(--green);box-shadow:0 0 6px var(--green)}
.sdot-r{background:var(--red)}
#refresh-ts{font-size:11px;font-weight:normal;color:var(--muted);margin-left:8px}
/* global refresh bar in nav */
.nav-refresh{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted)}
.nav-refresh select{background:var(--bg);color:var(--muted);border:1px solid var(--border);
  padding:2px 6px;border-radius:3px;font-size:11px;cursor:pointer;font-family:var(--font)}
#nav-last-updated{font-size:10px;color:var(--muted);white-space:nowrap}
/* T7: ensure no element causes horizontal overflow */
.tbl-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;max-width:100%}
.card{overflow:hidden}               /* T7: cards clip their content */
.mac{color:var(--yellow);font-size:11px;word-break:break-all}
body{overflow-x:hidden}
/* hamburger nav */
.nav-links{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.nav-hamburger{display:none;background:none;border:1px solid var(--border);
  color:var(--text);padding:4px 10px;border-radius:4px;cursor:pointer;
  font-size:18px;font-family:var(--font);line-height:1}
@media(max-width:768px){
  nav{flex-wrap:wrap;gap:8px;padding:10px 12px;position:relative}
  .nav-hamburger{display:block}
  .nav-links{display:none;width:100%;flex-direction:column;align-items:flex-start;
             gap:6px;padding:8px 0;border-top:1px solid var(--border);margin-top:6px}
  .nav-links.open{display:flex}
  .nav-refresh{margin-left:0!important;width:100%}
  .container{padding:10px}
  .stat-grid{grid-template-columns:repeat(2,1fr);gap:10px}
  .login-box{width:95%;padding:22px 14px}
  .card{padding:12px}
  h1{font-size:16px;margin-bottom:14px}
  /* T7: stack form rows on mobile */
  form[style*="grid"]{display:flex;flex-direction:column}
}
@media(max-width:480px){
  .stat-grid{grid-template-columns:1fr}
  table{font-size:11px}              /* T7: smaller font on very small screens */
  th,td{padding:5px 6px}
  .stat-value{font-size:20px}
}
</style>"""


def _nav(active: str) -> str:
    """Build nav bar with hamburger menu (mobile), refresh selector, and subnet selector."""
    pages = [
        ("home",         "index",        "Overview"),
        ("devices",      "devices",      "Devices"),
        ("anomalies",    "anomalies",    "Anomalies"),
        ("top",          "top_devices",  "Top Active"),
        ("device-types", "device_types", "Device Types"),
        ("diag",         "diag_page",    "Diagnostics"),
        ("capture",      "capture_page", "Capture"),
    ]
    # TASK 6: hamburger button — toggles .nav-links.open via JS
    html = ('<nav>'
            '<span class="logo">⬡ PINETAID</span>'
            '<button class="nav-hamburger" onclick="'
            'document.getElementById(\'nav-links\').classList.toggle(\'open\')">'
            '☰</button>'
            '<div class="nav-links" id="nav-links">')

    for key, endpoint, label in pages:
        cls = ' class="nav-active"' if active == key else ""
        html += f'<a href="{url_for(endpoint)}"{cls}>{label}</a>'

    html += '</div>'  # close .nav-links

    # Capture status pill — updated every 2s by PNA._pollStatus
    html += ('<span id="nav-cap-pill" style="font-size:11px;color:var(--muted)">'
             '<span class="sdot sdot-r"></span>Stopped</span>')

    # TASK 1/3: subnet selector — populated and persisted by JS
    html += (
        '<span style="font-size:11px;color:var(--muted)">Subnet:</span>'
        '<select id="nav-subnet-sel" onchange="PNA.setSubnet(this.value)"'
        ' style="background:var(--bg);color:var(--muted);border:1px solid var(--border);'
        'padding:2px 6px;border-radius:3px;font-size:11px;cursor:pointer;'
        'font-family:var(--font);max-width:130px">'
        '<option value="">All</option>'
        '</select>'
    )

    # Global refresh selector — persisted via localStorage
    html += (
        '<div class="nav-refresh" style="margin-left:auto">'
        '↺ <select id="nav-refresh-sel" onchange="PNA.setRefresh(+this.value)">'
        '<option value="5000">5 s</option>'
        '<option value="30000">30 s</option>'
        '<option value="60000">1 min</option>'
        '</select>'
        # TASK 7: always-visible last-updated timestamp
        '<span id="nav-last-updated" style="white-space:nowrap"></span>'
        '</div>'
    )

    _nb = ('font-size:11px;padding:3px 8px;border:1px solid var(--border);'
           'border-radius:3px;color:var(--muted);text-decoration:none')
    if _WIFI_AVAILABLE:
        try:
            html += f'<a href="{url_for("wifi_setup")}" style="{_nb};margin-left:auto">WiFi</a>'
        except Exception:
            pass
    html += f'<a href="{url_for("logout")}" style="{_nb};margin-left:6px">Logout</a></nav>'
    return html


def _flashes() -> str:
    """Render flash messages without Jinja block tags."""
    msgs = get_flashed_messages(with_categories=True)
    if not msgs:
        return ""
    cat_map = {"error": "al-e", "success": "al-s", "info": "al-i"}
    out = '<div class="container" style="padding-bottom:0">'
    for cat, msg in msgs:
        out += f'<div class="alert {cat_map.get(cat,"al-i")}">{msg}</div>'
    return out + "</div>"


def render_page(content: str, active: str = "", title: str = "") -> str:
    """Assemble a complete HTML page. Injects global PNA JS on every authenticated page."""
    t = title or active.capitalize()
    nav = _nav(active) if session.get("logged_in") else ""

    # Global JS injected on every authenticated page.
    global_js = """<script>
var PNA = (function(){
  // Read saved values BEFORE any timer starts (TASK 7)
  var _ms     = parseInt(localStorage.getItem('pna_refresh') || '5000');
  // TASK 1: empty string means "All" — never fall back to auto-detect in JS
  var _subnet = localStorage.getItem('pna_subnet');
  if(_subnet === null) _subnet = '';   // first visit: default to All
  var _timer  = null;
  var _refreshFn = null;

  // Build a URL with the current subnet appended as ?subnet=
  // Used by all AJAX fetches on all pages.
  function withSubnet(url){
    var s = _subnet;
    if(!s || s === 'all' || s === 'All') return url;
    var sep = url.indexOf('?') >= 0 ? '&' : '?';
    return url + sep + 'subnet=' + encodeURIComponent(s);
  }

  // Build fetch URL for /api/devices — always includes subnet
  function devicesUrl(){
    var s = _subnet || 'all';
    return '/api/devices?subnet=' + encodeURIComponent(s);
  }

  // Build status/stats URL with current subnet
  function statusUrl(){
    var s = _subnet || 'all';
    return '/api/status?subnet=' + encodeURIComponent(s);
  }

  // Change subnet, persist, then reload the current page with ?subnet= so
  // server-rendered pages (anomalies, top, suspicious, device-types) update too.
  function setSubnet(val){
    _subnet = val;
    localStorage.setItem('pna_subnet', val);
    // Reload with subnet in URL so ALL pages filter correctly
    var url = window.location.pathname;
    if(val && val !== 'all' && val !== 'All'){
      url += '?subnet=' + encodeURIComponent(val);
    }
    window.location.href = url;
  }

  // Expose for deleteSubnet() button
  function getSubnet(){ return _subnet; }

  // Populate nav subnet dropdown from /api/subnets.
  // Also reads ?subnet= from the current URL so the dropdown matches the page.
  function _loadSubnets(){
    // Read subnet from URL to keep nav in sync with server-rendered pages
    var urlParams = new URLSearchParams(window.location.search);
    var urlSubnet = urlParams.get('subnet');
    if(urlSubnet !== null){
      _subnet = urlSubnet;
      localStorage.setItem('pna_subnet', urlSubnet);
    }

    fetch('/api/subnets').then(function(r){ return r.json(); }).then(function(data){
      var sel = document.getElementById('nav-subnet-sel');
      if(!sel) return;
      var opts = '<option value="">All</option>';
      data.subnets.forEach(function(s){
        var selected = (s === _subnet) ? ' selected' : '';
        opts += '<option value="' + s + '"' + selected + '>' + s + '</option>';
      });
      sel.innerHTML = opts;
      if(!_subnet) sel.value = '';
    }).catch(function(){});
  }

  // timeAgo — identical wording on every page (TASK 7)
  function timeAgo(ts){
    if(!ts) return '\u2014';
    var d = new Date(ts.replace(' ','T')+'Z');
    var s = Math.floor((Date.now() - d) / 1000);
    if(isNaN(s) || s < 0) return ts;
    if(s < 60)    return s + ' sec ago';
    if(s < 3600)  return Math.floor(s/60) + ' min ago';
    if(s < 86400) return Math.floor(s/3600) + ' hr ago';
    return Math.floor(s/86400) + ' day ago';
  }

  // Device type classification — mirrors _device_type_label() in Python exactly.
  // IoT is ONLY returned when the vendor explicitly matches IoT-specific terms.
  // Low packet_count does NOT automatically mean IoT.
  function deviceType(vendor, mac, pkt){
    var v = (vendor || '').toLowerCase();
    pkt = pkt || 0;

    // Step 1: vendor keyword (skip if vendor string says "unknown")
    if(v && v.indexOf('unknown') === -1){
      if(/cisco|ubiquiti|netgear|tp-link|tplink|d-link|dlink|zyxel|mikrotik|linksys|unifi|aruba|fortinet|juniper/.test(v))
        return 'Network Device';
      if(/intel|dell|hp |lenovo|asus|acer|microsoft|msi |gigabyte|asrock|toshiba|supermicro/.test(v))
        return 'PC / Laptop';
      if(/apple|samsung|oneplus|huawei|oppo|vivo|xiaomi|realme|motorola|nokia|pixel|lg |zte|alcatel/.test(v))
        return 'Mobile';
      // IoT only when vendor explicitly matches IoT-specific terms
      if(/raspberry|espressif|esp8266|esp32|tuya|sonoff|tasmota|ewelink|shelly|arduino|lifx|broadlink|wemo|nest|philips hue|\biot\b/.test(v))
        return 'IoT';
    }

    // Step 2: locally-administered MAC bit → random MAC → Mobile
    if(mac){
      var fb = parseInt((mac.split(':')[0] || mac.split('-')[0] || '0'), 16);
      if(!isNaN(fb) && (fb & 0x02)) return 'Mobile';
    }

    // Step 3: behavior — only high-traffic hint; low traffic is NOT automatically IoT
    if(pkt > 500) return 'PC / Laptop';

    // Step 4: unknown — do NOT default to IoT
    return 'Unknown Device';
  }

  // TASK 7: always shows "Updated HH:MM:SS", called on EVERY poll cycle
  function markUpdated(){
    var el = document.getElementById('nav-last-updated');
    if(!el) return;
    var t  = new Date();
    var hh = String(t.getHours()).padStart(2,'0');
    var mm = String(t.getMinutes()).padStart(2,'0');
    var ss = String(t.getSeconds()).padStart(2,'0');
    el.textContent = ' Updated: ' + hh + ':' + mm + ':' + ss;
  }

  // Register page refresh fn — run once immediately, then on interval
  function register(fn){
    _refreshFn = fn;
    if(_timer) clearInterval(_timer);
    fn();
    _timer = setInterval(_refreshFn, _ms);
  }

  function setRefresh(ms){
    _ms = ms;
    localStorage.setItem('pna_refresh', ms);
    if(_timer) clearInterval(_timer);
    if(_refreshFn) _timer = setInterval(_refreshFn, _ms);
  }

  // Poll /api/status every 2s — uses subnet-scoped URL (TASK 1)
  function _pollStatus(){
    fetch(statusUrl()).then(function(r){ return r.json(); }).then(function(s){
      var running = !!s.capture_running;

      // Nav capture pill
      var pill = document.getElementById('nav-cap-pill');
      if(pill){
        pill.innerHTML = running
          ? '<span class="sdot sdot-g"></span><span style="color:var(--green)">Live</span>'
          : '<span class="sdot sdot-r"></span><span style="color:var(--muted)">Stopped</span>';
      }

      // Capture page: delegate to _updateCapUI() defined in capture_page JS.
      // Only present on /capture — safe to call conditionally.
      if(typeof _updateCapUI === 'function') _updateCapUI(running);

      // Always tick the "Last Updated" clock
      markUpdated();
    }).catch(function(){});
  }

  _pollStatus();
  setInterval(_pollStatus, 2000);

  document.addEventListener('DOMContentLoaded', function(){
    var rsel = document.getElementById('nav-refresh-sel');
    if(rsel) rsel.value = String(_ms);
    _loadSubnets();
  });

  return { timeAgo:timeAgo, deviceType:deviceType,
           devicesUrl:devicesUrl, statusUrl:statusUrl, withSubnet:withSubnet,
           markUpdated:markUpdated, register:register,
           setRefresh:setRefresh, setSubnet:setSubnet, getSubnet:getSubnet };
})();
</script>""" if session.get("logged_in") else ""

    return (f"<!DOCTYPE html><html lang='en'><head>"
            f"<meta charset='UTF-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1.0'>"
            f"<title>PiNetAid{(' · ' + t) if t else ''}</title>"
            f"{_CSS}</head><body>{nav}{_flashes()}{content}{global_js}</body></html>")


# ─────────────────────────────────────────────────────────────────────────────
# Auth routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if not user_exists():
        return redirect(url_for("setup"))

    error = ""
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if verify_user(u, p):
            session["logged_in"] = True
            session["username"]  = u
            return redirect(request.args.get("next") or url_for("index"))
        error = "Invalid username or password."

    err_html = f'<div class="alert al-e">{error}</div>' if error else ""
    content = f"""
<div class="login-wrap"><div class="login-box">
  <div class="login-logo">PINETAID</div>
  <div class="login-sub">Network Monitoring · Offline</div>
  {err_html}
  <form method="POST">
    <div class="form-group"><label>Username</label>
      <input type="text" name="username" autofocus required></div>
    <div class="form-group"><label>Password</label>
      <input type="password" name="password" required></div>
    <button class="btn btn-g" type="submit" style="width:100%">LOGIN</button>
  </form>
</div></div>"""
    return render_page(content, title="Login")


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if user_exists():
        return redirect(url_for("login"))
    error = ""
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        c = request.form.get("confirm",  "")
        if not u or not p:
            error = "Username and password are required."
        elif p != c:
            error = "Passwords do not match."
        else:
            create_user(u, p)
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))

    err_html = f'<div class="alert al-e">{error}</div>' if error else ""
    content = f"""
<div class="login-wrap"><div class="login-box">
  <div class="login-logo">PINETAID</div>
  <div class="login-sub">First-run Setup</div>
  {err_html}
  <form method="POST">
    <div class="form-group"><label>Admin Username</label>
      <input type="text" name="username" autofocus required></div>
    <div class="form-group"><label>Password</label>
      <input type="password" name="password" required></div>
    <div class="form-group"><label>Confirm Password</label>
      <input type="password" name="confirm" required></div>
    <button class="btn btn-g" type="submit" style="width:100%">CREATE ACCOUNT</button>
  </form>
</div></div>"""
    return render_page(content, title="Setup")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─────────────────────────────────────────────────────────────────────────────
# Overview  (TASK 2: all devices | TASK 3: AJAX | TASK 6: health banner)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    db = Database()

    # Read subnet filter first — all counts must reflect it (TASK 1)
    current_subnet = request.args.get("subnet", "").strip()
    if current_subnet == "all":
        current_subnet = ""

    # All counts now scoped to selected subnet
    device_count     = db.device_count(subnet=current_subnet)
    anomaly_count    = db.anomaly_count(subnet=current_subnet)
    recent_anomalies = db.get_anomalies(limit=5)
    health           = db.get_network_health(subnet=current_subnet)

    all_devices = db.get_all_devices(subnet=current_subnet) if current_subnet \
                  else db.get_all_devices()
    all_subnets = db.get_subnets()
    db.close()

    # TASK 4: network info (gateway, broadcast, local IP) — lightweight, cached per request
    net_info = _get_network_info()

    # TASK 1: subnet selector — always show "All" + list of known subnets.
    # The server renders the initial state; the nav dropdown JS is the live control.
    subnet_html = ""
    if all_subnets:
        opts_html = '<option value="">All</option>'
        for s in all_subnets:
            sel = 'selected' if s == current_subnet else ''
            opts_html += f"<option value='{s}' {sel}>{s}</option>"
        subnet_html = (
            f"<select id='page-subnet-sel' "
            f"onchange=\"PNA.setSubnet(this.value);location.href='/?subnet='+encodeURIComponent(this.value)\" "
            f"style=\"background:var(--bg);color:var(--muted);border:1px solid var(--border);"
            f"padding:3px 8px;border-radius:4px;font-size:11px;margin-left:8px\">"
            f"{opts_html}</select>"
        )

    cap_running = capture_is_running()

    # TASK 3: Delete button is ALWAYS visible — JS handles both specific subnet and "All"
    delete_btn = (
        "<button id='delete-subnet-btn' class='btn btn-r' "
        "style='font-size:11px;padding:4px 10px;margin-left:8px' "
        "onclick='deleteSubnet()'>🗑 Delete Subnet Data</button>"
    )
    cap_label   = "LIVE" if cap_running else "OFF"
    cap_cls     = "c-green" if cap_running else "c-red"
    h_cls       = {"Good": "c-green", "Warning": "c-yellow", "Critical": "c-red"}[health["status"]]
    ac_cls      = "c-red" if anomaly_count > 0 else "c-green"

    # Device rows for initial render
    dev_rows = _device_rows_html(all_devices)

    # Anomaly rows
    anm_html = ""
    if recent_anomalies:
        rows = ""
        for a in recent_anomalies:
            rows += (f"<tr><td class='mac'>{a['mac']}</td>"
                     f"<td>{a.get('ip') or '—'}</td>"
                     f"<td class='muted'>{a.get('vendor') or '—'}</td>"
                     f"<td class='c-red'>{a.get('score','')}</td>"
                     f"<td style='font-size:11px'>{a.get('reason','') or '—'}</td>"
                     f"<td class='muted'>{a.get('created_at','')}</td></tr>")
        anm_html = (f"<div class='card'><h2>Recent Anomalies</h2>"
                    f"<table><thead><tr><th>MAC</th><th>IP</th><th>Vendor</th>"
                    f"<th>Score</th><th>Reason</th><th>Detected</th></tr></thead>"
                    f"<tbody>{rows}</tbody></table></div>")

    # TASK 1/2/3: page-local scripts
    ajax = """<script>
// TASK 1: refresh device table and stat counters together using current subnet
function refreshDevices(){
  var url = PNA.devicesUrl();
  var statsUrl = PNA.statusUrl();

  // Refresh stats (device count, anomaly count)
  fetch(statsUrl).then(function(r){ return r.json(); }).then(function(s){
    var dc = document.getElementById('dev-count');
    var ac = document.getElementById('anom-count');
    if(dc && s.device_count !== undefined) dc.textContent = s.device_count;
    if(ac && s.anomaly_count !== undefined) ac.textContent = s.anomaly_count;
  }).catch(function(){});

  // Refresh device rows
  fetch(url).then(function(r){ return r.json(); }).then(function(data){
    var tb = document.getElementById('dev-tbody');
    if(!tb) return;
    var h = '';
    data.forEach(function(d){
      var dtype = PNA.deviceType(d.vendor, d.mac, d.packet_count);
      h += '<tr><td>' + (d.ip||'\u2014') + '</td>'
         + '<td class="mac">' + d.mac + '</td>'
         + '<td><span class="badge badge-type">' + dtype + '</span></td>'
         + '<td class="muted">' + PNA.timeAgo(d.last_seen) + '</td></tr>';
    });
    tb.innerHTML = h || '<tr><td colspan="4" class="muted">No devices on this subnet.</td></tr>';
    PNA.markUpdated();
  }).catch(function(){});
}

// Delete subnet — works for specific subnet AND "All" (empty string)
window.deleteSubnet = function(){
  var urlSubnet = new URLSearchParams(window.location.search).get('subnet') || '';
  var isAll = (!urlSubnet || urlSubnet.toLowerCase() === 'all');
  var payload = isAll ? 'All' : urlSubnet;
  if(!confirm('Confirm delete?')) return;
  fetch('/api/delete_subnet', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({subnet: payload})
  })
  .then(function(r){ return r.json(); })
  .then(function(d){
    if(d.status !== 'ok'){ alert('Delete failed'); return; }
    location.reload();
  })
  .catch(function(err){
    console.error(err);
    alert('Request failed');
  });
};
console.log("deleteSubnet LOADED OK");

document.addEventListener('DOMContentLoaded', function(){
  PNA.register(refreshDevices);

  // Sync page-level subnet selector with the URL param (set by setSubnet reload)
  var urlParams = new URLSearchParams(window.location.search);
  var urlSubnet = urlParams.get('subnet') || '';
  var pageSel   = document.getElementById('page-subnet-sel');
  if(pageSel) pageSel.value = urlSubnet;
  // Note: delete button is always visible — works for All and specific subnets
});
</script>"""

    no_dev = '<p class="muted">No devices yet. Start capture to begin.</p>'
    dev_table = (
        f"<div class='tbl-wrap'><table><thead><tr><th>IP</th><th>MAC</th><th>Type</th>"
        f"<th>Last Seen</th></tr></thead>"
        f"<tbody id='dev-tbody'>{dev_rows}</tbody></table></div>"
        if all_devices else no_dev
    )

    content = f"""
<div class="container">
  <h1>Network Overview {subnet_html}{delete_btn}</h1>

  <!-- Health banner -->
  <div class="card" style="border-left:3px solid var(--{health['color']});padding:12px 20px">
    <strong>Network Health:</strong> <span class="{h_cls}">{health['status']}</span>
    &nbsp;·&nbsp;<span class="muted">{health['anomaly_count']} anomaly(ies)
    &nbsp;|&nbsp; {health['new_devices']} new device(s) in last 10 min</span>
    <span class="muted" style="margin-left:16px;font-size:11px">
      {f'Gateway: <strong>{net_info["gateway"]}</strong>' if net_info["gateway"] else ''}
      {f'&nbsp;·&nbsp; Broadcast: <strong>{net_info["broadcast"]}</strong>' if net_info["broadcast"] else ''}
      {f'&nbsp;·&nbsp; Local IP: <strong>{net_info["local_ip"]}</strong>' if net_info["local_ip"] else ''}
    </span>
  </div>

  <!-- Stats — id="anom-count" lets AJAX update the anomaly counter (TASK 1) -->
  <div class="stat-grid">
    <div class="stat"><div class="stat-label">Devices Seen</div>
      <div class="stat-value c-blue" id="dev-count">{device_count}</div></div>
    <div class="stat"><div class="stat-label">Anomalies</div>
      <div class="stat-value {ac_cls}" id="anom-count">{anomaly_count}</div></div>
    <div class="stat"><div class="stat-label">Capture</div>
      <div class="stat-value">
        <span class="sdot {'sdot-g' if cap_running else 'sdot-r'}" id="cap-dot"></span>
        <strong id="cap-label" class="{'c-green' if cap_running else 'c-red'}">{cap_label}</strong>
      </div></div>
    <div class="stat"><div class="stat-label">Health</div>
      <div class="stat-value {h_cls}">{health['status']}</div></div>
  </div>

  <!-- Device table -->
  <div class="card">
    <h2>All Devices</h2>
    {dev_table}
  </div>

  {anm_html}
</div>
{ajax}"""
    return render_page(content, active="home", title="Overview")


def _device_type_label(vendor: str, mac: str = "", packet_count: int = 0) -> str:
    """
    Priority order (per spec):
      1. Vendor keyword
      2. Locally-administered MAC bit → Mobile
      3. Behavior: only packet_count > 500 → PC/Laptop
      4. "Unknown Device" — NOT IoT by default
    IoT is only returned when the vendor explicitly matches IoT keywords.
    """
    import re
    v = (vendor or "").lower()

    # Step 1: vendor keywords — skip if string already says "unknown"
    if v and "unknown" not in v:
        if re.search(r'cisco|ubiquiti|netgear|tp-link|tplink|d-link|dlink|zyxel|'
                     r'mikrotik|linksys|unifi|aruba|fortinet|juniper', v):
            return "Network Device"
        if re.search(r'intel|dell|hp |lenovo|asus|acer|microsoft|'
                     r'msi |gigabyte|asrock|toshiba|supermicro', v):
            return "PC / Laptop"
        if re.search(r'apple|samsung|oneplus|huawei|oppo|vivo|xiaomi|'
                     r'realme|motorola|nokia|pixel|lg |zte|alcatel', v):
            return "Mobile"
        # IoT only when vendor explicitly matches IoT-specific terms
        if re.search(r'raspberry|espressif|esp8266|esp32|tuya|sonoff|'
                     r'tasmota|ewelink|shelly|arduino|lifx|broadlink|'
                     r'wemo|nest|philips hue|\biot\b', v):
            return "IoT"

    # Step 2: locally-administered MAC bit → random MAC → Mobile
    if mac:
        try:
            first_byte = int(mac.replace("-", ":").split(":")[0], 16)
            if first_byte & 0x02:
                return "Mobile"
        except (ValueError, IndexError):
            pass

    # Step 3: behavior — ONLY high-traffic hint; low traffic is NOT automatically IoT
    if packet_count > 500:
        return "PC / Laptop"

    # Step 4: unknown — do NOT default to IoT
    return "Unknown Device"


def _time_ago_server(ts: str) -> str:
    """
    TASK 3: Server-side version of timeAgo for the initial HTML render.
    Produces identical wording to PNA.timeAgo() in JS:
    'X sec ago' / 'X min ago' / 'X hr ago' / 'X day ago'.
    """
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("T", " ").split(".")[0])
        s = int((datetime.utcnow() - dt).total_seconds())
        if s < 0:
            return ts
        if s < 60:
            return f"{s} sec ago"
        if s < 3600:
            return f"{s // 60} min ago"
        if s < 86400:
            return f"{s // 3600} hr ago"
        return f"{s // 86400} day ago"
    except Exception:
        return ts


def _device_rows_html(devices: list) -> str:
    """Server-rendered device rows — uses packet_count for behavior-based type."""
    rows = ""
    for d in devices:
        mac   = d['mac']
        pkt   = d.get('packet_count') or 0
        dtype = _device_type_label(d.get('vendor') or '', mac, pkt)
        rows += (f"<tr><td>{d.get('ip') or '—'}</td>"
                 f"<td class='mac'>{d['mac']}</td>"
                 f"<td><span class='badge badge-type'>{dtype}</span></td>"
                 f"<td class='muted'>{_time_ago_server(d.get('last_seen',''))}</td></tr>")
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Devices page (TASK 2: unlimited | TASK 3: AJAX refresh)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/devices")
@login_required
def devices():
    db = Database()
    # AJAX will request the right subnet via PNA.devicesUrl()
    all_devices = db.get_all_devices()
    db.close()

    rows = ""
    for d in all_devices:
        dtype = _device_type_label(d.get('vendor') or '', d.get('mac',''))  # TASK 5
        rows += (f"<tr><td>{d.get('ip') or '—'}</td>"
                 f"<td class='mac'>{d['mac']}</td>"
                 f"<td><span class='badge badge-type'>{dtype}</span></td>"
                 f"<td class='muted'>{_time_ago_server(d.get('first_seen',''))}</td>"
                 f"<td class='muted'>{_time_ago_server(d.get('last_seen',''))}</td></tr>")

    ajax = """<script>
function refreshDevices(){
  fetch(PNA.devicesUrl())          // TASK 3: includes ?subnet= from nav selector
    .then(function(r){ return r.json(); })
    .then(function(data){
      var tb = document.getElementById('dtbl'); if(!tb) return;
      var h = '';
      data.forEach(function(d){
        var dtype = PNA.deviceType(d.vendor, d.mac, d.packet_count);
        h += '<tr><td>' + (d.ip||'\u2014') + '</td>'
           + '<td class="mac">' + d.mac + '</td>'
           + '<td><span class="badge badge-type">' + dtype + '</span></td>'
           + '<td class="muted">' + PNA.timeAgo(d.first_seen) + '</td>'
           + '<td class="muted">' + PNA.timeAgo(d.last_seen)  + '</td></tr>';
      });
      tb.innerHTML = h;
      var c = document.getElementById('dcnt');
      if(c) c.textContent = '(' + data.length + ')';
      PNA.markUpdated();
    }).catch(function(){});
}
document.addEventListener('DOMContentLoaded', function(){
  PNA.register(refreshDevices);
});
</script>"""

    no_dev = '<p class="muted">No devices captured yet.</p>'
    table = (f"<div class='tbl-wrap'><table><thead><tr><th>IP Address</th><th>MAC Address</th><th>Type</th>"
             f"<th>First Seen</th><th>Last Seen</th></tr></thead>"
             f"<tbody id='dtbl'>{rows}</tbody></table></div>"
             if all_devices else no_dev)

    # Refresh interval is now in the global nav bar (TASK 3)
    content = f"""
<div class="container">
  <h1 style="display:flex;align-items:center">
    Connected Devices <span id="dcnt" style="margin-left:6px">({len(all_devices)})</span>
  </h1>
  <div class="card">{table}</div>
</div>
{ajax}"""
    return render_page(content, active="devices", title="Devices")


# ─────────────────────────────────────────────────────────────────────────────
# Anomalies (TASK 4: shows reason column)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/anomalies", methods=["GET", "POST"])
@login_required
def anomalies():
    """
    Three-tab anomaly page:
      Tab 1 — Current Anomalies: deduplicated by (mac, rule-type) so each
               device+rule appears only once even if multiple runs fired it.
      Tab 2 — Suspicious: one row per MAC, highest score wins, count shown.
      Tab 3 — AI History: one row per MAC from ai_history, with status and
               resolved_reason filled by the AI engine after each run.
    """
    db     = Database()
    subnet = request.args.get("subnet", "").strip() or None

    if request.method == "POST":
        res = run_full_analysis()
        flash(f"Analysis complete — {len(res['anomalies'])} anomalie(s) detected.", "success")

    all_anom   = db.get_anomalies(limit=500, subnet=subnet)
    ai_history = db.get_anomaly_history(limit=300, subnet=subnet)
    db.close()

    SEV_CLS = {"Critical": "sev-critical", "High": "sev-high",
               "Medium":   "sev-medium",   "Low":  "sev-low"}

    # ── Tab 1: deduplicate by (mac, rule-type prefix) ─────────────────────
    # Keep only the latest row per unique device+rule combination.
    # This prevents the same "IP conflict" message appearing 20 times for
    # the same MAC when multiple analysis runs fired within the window.
    dedup_anom: dict = {}
    for a in all_anom:
        # The rule prefix is everything before the first " – " or ":"
        raw_reason = a.get("reason") or ""
        prefix = raw_reason.split(" – ")[0].split(":")[0].strip()
        key = (a["mac"], prefix)
        # all_anom is already ordered newest-first; first hit wins
        if key not in dedup_anom:
            dedup_anom[key] = a
    deduped = list(dedup_anom.values())

    anom_rows = ""
    for a in deduped:
        sev     = a.get("severity") or "Low"
        sev_cls = SEV_CLS.get(sev, "sev-low")
        anom_rows += (
            f"<tr><td class='mac'>{a['mac']}</td>"
            f"<td>{a.get('ip') or '—'}</td>"
            f"<td class='muted'>{a.get('vendor') or '—'}</td>"
            f"<td class='c-red'>{a.get('score','')}</td>"
            f"<td><span class='badge {sev_cls}'>{sev}</span></td>"
            f"<td style='font-size:11px;max-width:240px'>{a.get('reason') or '—'}</td>"
            f"<td class='muted'>{a.get('created_at','')}</td></tr>"
        )
    anom_empty = '<p class="muted">No anomalies detected. Run analysis to start.</p>'
    anom_table = (
        f"<table><thead><tr><th>MAC</th><th>IP</th><th>Vendor</th>"
        f"<th>Score</th><th>Severity</th><th>Reason</th><th>Detected</th>"
        f"</tr></thead><tbody>{anom_rows}</tbody></table>"
        if deduped else anom_empty
    )

    # ── Tab 2: one row per MAC, count of detections, highest score ────────
    susp_map: dict = {}
    for a in all_anom:
        mac = a["mac"]
        if mac not in susp_map:
            susp_map[mac] = dict(a)
            susp_map[mac]["count"] = 1
        else:
            susp_map[mac]["count"] += 1
            if (a.get("score") or 0) > (susp_map[mac].get("score") or 0):
                susp_map[mac].update(a)
                susp_map[mac]["count"] = susp_map[mac]["count"]  # keep count
    susp = sorted(susp_map.values(), key=lambda x: x.get("score") or 0, reverse=True)

    susp_rows = ""
    for d in susp:
        sev     = d.get("severity") or "Low"
        sev_cls = SEV_CLS.get(sev, "sev-low")
        susp_rows += (
            f"<tr><td class='mac'>{d['mac']}</td>"
            f"<td>{d.get('ip') or '—'}</td>"
            f"<td class='muted'>{d.get('vendor') or '—'}</td>"
            f"<td><span class='badge {sev_cls}'>{sev}</span></td>"
            f"<td class='c-red'>{d.get('score','')}</td>"
            f"<td style='font-size:11px;max-width:200px'>{d.get('reason','') or '—'}</td>"
            f"<td style='text-align:center'>{d.get('count',1)}</td>"
            f"<td class='muted'>{d.get('created_at','')}</td></tr>"
        )
    susp_empty = '<p class="muted">No suspicious devices.</p>'
    susp_table = (
        f"<table><thead><tr><th>MAC</th><th>IP</th><th>Vendor</th>"
        f"<th>Severity</th><th>Score</th><th>Latest Reason</th>"
        f"<th>Detections</th><th>Last Flagged</th>"
        f"</tr></thead><tbody>{susp_rows}</tbody></table>"
        if susp else susp_empty
    )

    # ── Tab 3: AI History — one row per MAC, status + resolved reason ─────
    hist_rows = ""
    for h in ai_history:
        sev     = h.get("severity") or "Low"
        sev_cls = SEV_CLS.get(sev, "sev-low")
        status  = h.get("status") or "active"
        status_badge = (
            '<span class="badge badge-ok">Resolved</span>'
            if status == "resolved" else
            '<span class="badge sev-high">Active</span>'
        )
        resolved_note = h.get("resolved_reason") or ""
        if not resolved_note and h.get("resolved_at"):
            resolved_note = "Marked resolved"
        device_display = h.get("device_type") or h.get("vendor") or "—"
        hist_rows += (
            f"<tr><td class='mac'>{h.get('mac','')}</td>"
            f"<td>{h.get('ip') or '—'}</td>"
            f"<td class='muted'>{device_display}</td>"
            f"<td>{status_badge}</td>"
            f"<td><span class='badge {sev_cls}'>{sev}</span></td>"
            f"<td style='font-size:11px;max-width:200px'>{h.get('reason','') or '—'}</td>"
            f"<td style='font-size:11px;max-width:180px;color:var(--green)'>{resolved_note or '—'}</td>"
            f"<td class='muted'>{h.get('first_detected','')}</td>"
            f"<td class='muted'>{h.get('last_updated','')}</td></tr>"
        )
    hist_empty = (
        '<p class="muted">No AI history yet. Run an analysis to populate.<br>'
        '<small>History is stored in <code>ai_history</code> &mdash; '
        'one row per MAC, updated in-place (no duplicates).</small></p>'
    )
    hist_table = (
        f"<table><thead><tr><th>MAC</th><th>IP</th><th>Device</th>"
        f"<th>Status</th><th>Severity</th><th>Reason</th>"
        f"<th>Resolved Because</th><th>First Detected</th><th>Last Updated</th>"
        f"</tr></thead><tbody>{hist_rows}</tbody></table>"
        if ai_history else hist_empty
    )

    _btn = ("padding:8px 16px;font-size:12px;cursor:pointer;"
            "border:1px solid var(--border);border-radius:4px 4px 0 0;"
            "font-family:var(--font);margin-right:2px;background:var(--bg);"
            "color:var(--muted)")

    # Tab JS is a plain string (not f-string) to avoid brace-escaping issues
    tab_js = """
<script>
(function () {
  var panes = ['tab-anom', 'tab-susp', 'tab-hist'];
  var btns  = ['btn-anom', 'btn-susp', 'btn-hist'];

  window.showAnomalyTab = function (id) {
    panes.forEach(function (p, i) {
      var show = (p === id);
      document.getElementById(p).style.display = show ? 'block' : 'none';
      var b = document.getElementById(btns[i]);
      if (b) {
        b.style.background  = show ? 'var(--surface)' : 'var(--bg)';
        b.style.color       = show ? 'var(--text)'    : 'var(--muted)';
      }
    });
  };

  showAnomalyTab('tab-anom');
})();
</script>"""

    content = f"""
<div class="container">
  <h1>Anomaly Detection</h1>
  <div class="card" style="display:flex;align-items:center;gap:16px;margin-bottom:12px">
    <div style="flex:1"><strong>Run AI Analysis</strong><br>
      <span class="muted">Rule engine (ARP flood &middot; IP conflict &middot; new device
      &middot; traffic spike) + Isolation Forest.</span></div>
    <form method="POST">
      <button class="btn btn-g" type="submit">&#9654; RUN ANALYSIS</button>
    </form>
  </div>

  <div style="margin-bottom:-1px">
    <button id="btn-anom" onclick="showAnomalyTab('tab-anom')" style="{_btn}">
      Current Anomalies ({len(deduped)})</button>
    <button id="btn-susp" onclick="showAnomalyTab('tab-susp')" style="{_btn}">
      Suspicious ({len(susp)})</button>
    <button id="btn-hist" onclick="showAnomalyTab('tab-hist')" style="{_btn}">
      AI History ({len(ai_history)})</button>
  </div>

  <div id="tab-anom" class="card" style="border-radius:0 4px 4px 4px">
    <h2>Current Anomalies &mdash; one row per device+rule</h2>
    {anom_table}
  </div>
  <div id="tab-susp" class="card" style="border-radius:0 4px 4px 4px;display:none">
    <h2>Suspicious Devices &mdash; highest score per MAC</h2>
    {susp_table}
  </div>
  <div id="tab-hist" class="card" style="border-radius:0 4px 4px 4px;display:none">
    <h2>AI History &mdash; one lifecycle row per MAC</h2>
    <p class="muted" style="font-size:11px;margin-bottom:8px">
      Updated in-place after each analysis run. Resolved rows show why the
      anomaly cleared. Data source: <code>ai_history</code> table.
    </p>
    {hist_table}
  </div>
</div>""" + tab_js

    return render_page(content, active="anomalies", title="Anomalies")


# ─────────────────────────────────────────────────────────────────────────────
# TASK 6 Feature 1: Top Active Devices
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/top-devices")
@login_required
def top_devices():
    db = Database()
    subnet = request.args.get("subnet", "").strip() or None
    top = db.get_top_active_devices(limit=20, subnet=subnet)
    db.close()

    rows = ""
    for i, d in enumerate(top, 1):
        rows += (f"<tr><td>{i}</td><td class='mac'>{d['mac']}</td>"
                 f"<td>{d.get('ip') or '—'}</td>"
                 f"<td class='muted'>{d.get('vendor','Unknown')}</td>"
                 f"<td class='c-blue'><strong>{d['total_packets']}</strong></td></tr>")

    no_data = '<p class="muted">No traffic data yet. Start capture.</p>'
    table = (f"<table><thead><tr><th>#</th><th>MAC</th><th>IP</th>"
             f"<th>Vendor</th><th>Total Packets</th></tr></thead>"
             f"<tbody>{rows}</tbody></table>"
             if top else no_data)

    content = f"""
<div class="container">
  <h1>Top Active Devices</h1>
  <div class="card"><h2>Ranked by total packets captured</h2>{table}</div>
</div>"""
    return render_page(content, active="top", title="Top Active")


# ─────────────────────────────────────────────────────────────────────────────
# TASK 6 Feature 2: Suspicious Devices
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/suspicious")
@login_required
def suspicious():
    db = Database()
    subnet = request.args.get("subnet", "").strip() or None
    all_anom = db.get_anomalies(limit=500, subnet=subnet)
    db.close()

    # Deduplicate by MAC — keep highest-score entry
    seen: dict[str, dict] = {}
    for a in all_anom:
        mac = a["mac"]
        if mac not in seen or (a.get("score") or 0) > (seen[mac].get("score") or 0):
            seen[mac] = a

    susp = sorted(seen.values(), key=lambda x: x.get("score") or 0, reverse=True)

    rows = ""
    for d in susp:
        sev     = d.get("severity") or "Low"
        sev_cls = {"Critical": "sev-critical", "High": "sev-high",
                   "Medium": "sev-medium",   "Low":  "sev-low"}.get(sev, "sev-low")
        rows += (f"<tr><td class='mac'>{d['mac']}</td>"
                 f"<td>{d.get('ip') or '—'}</td>"
                 f"<td class='muted'>{d.get('vendor') or '—'}</td>"
                 f"<td><span class='badge {sev_cls}'>{sev}</span></td>"
                 f"<td class='c-red'>{d.get('score','')}</td>"
                 f"<td style='font-size:11px'>{d.get('reason','') or '—'}</td>"
                 f"<td class='muted'>{d.get('created_at','')}</td></tr>")

    no_data = '<p class="muted">No suspicious devices detected. Run analysis first.</p>'
    table = (f"<table><thead><tr><th>MAC</th><th>IP</th><th>Vendor</th>"
             f"<th>Severity</th><th>Score</th><th>Reason</th><th>Flagged At</th></tr></thead>"
             f"<tbody>{rows}</tbody></table>"
             if susp else no_data)

    content = f"""
<div class="container">
  <h1>Suspicious Devices ({len(susp)})</h1>
  <div class="alert al-i">
    Devices flagged by the anomaly engine. Go to Anomalies page to re-run analysis.
  </div>
  <div class="card">{table}</div>
</div>"""
    return render_page(content, active="suspicious", title="Suspicious")


# ─────────────────────────────────────────────────────────────────────────────
# TASK 6 Feature 4: Device Type Classification
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/device-types")
@login_required
def device_types():
    db = Database()
    subnet = request.args.get("subnet", "").strip() or None
    types = db.get_device_types(subnet=subnet)
    db.close()

    summary: dict[str, int] = {}
    for d in types:
        t = d["device_type"]
        summary[t] = summary.get(t, 0) + 1

    stat_html = "".join(
        f"<div class='stat'><div class='stat-label'>{dt}</div>"
        f"<div class='stat-value c-blue'>{cnt}</div></div>"
        for dt, cnt in sorted(summary.items())
    )

    rows = "".join(
        f"<tr><td class='mac'>{d['mac']}</td>"
        f"<td>{d.get('ip') or '—'}</td>"
        f"<td class='muted'>{d.get('vendor','Unknown')}</td>"
        f"<td><span class='badge badge-type'>{d['device_type']}</span></td></tr>"
        for d in types
    )

    no_data = '<p class="muted">No devices yet.</p>'
    table = (f"<table><thead><tr><th>MAC</th><th>IP</th><th>Vendor</th>"
             f"<th>Device Type</th></tr></thead><tbody>{rows}</tbody></table>"
             if types else no_data)

    content = f"""
<div class="container">
  <h1>Device Type Classification</h1>
  <div class="stat-grid">{stat_html}</div>
  <div class="card">
    <h2>Based on OUI vendor + traffic behaviour heuristics</h2>
    {table}
  </div>
</div>"""
    return render_page(content, active="device-types", title="Device Types")


# ─────────────────────────────────────────────────────────────────────────────
# Diagnostics
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/diagnostics", methods=["GET", "POST"])
@login_required
def diag_page():
    result_html = ""
    prev_target = ""

    if request.method == "POST":
        action     = request.form.get("action")
        target     = request.form.get("target", "").strip()
        prev_target = target
        result = None

        if action == "ping" and target:
            result = {"type": "ping", "data": ping(target)}
        elif action == "dns" and target:
            result = {"type": "dns", "data": dns_lookup(target)}
        elif action == "gateway":
            result = {"type": "gateway", "data": check_gateway()}

        if result:
            result_html = (f"<div class='card'><h2>Result · {result['type'].upper()}</h2>"
                           f"<div class='terminal'>"
                           f"{json.dumps(result['data'], indent=2)}"
                           f"</div></div>")

    content = f"""
<div class="container">
  <h1>Network Diagnostics</h1>
  <div class="card">
    <h2>Tools</h2>
    <form method="POST"
          style="display:grid;grid-template-columns:1fr auto auto;gap:12px;align-items:end">
      <div><label>Target (IP or Hostname)</label>
        <input type="text" name="target" placeholder="192.168.1.1 or hostname"
               value="{prev_target}"></div>
      <button class="btn btn-g" name="action" value="ping" type="submit">Ping</button>
      <button class="btn btn-g" name="action" value="dns"  type="submit">DNS Lookup</button>
    </form>
    <form method="POST" style="margin-top:12px">
      <button class="btn btn-s" name="action" value="gateway" type="submit">
        Check Gateway</button>
    </form>
  </div>
  {result_html}
</div>"""
    return render_page(content, active="diag", title="Diagnostics")


# ─────────────────────────────────────────────────────────────────────────────
# Capture
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/capture", methods=["GET"])
@login_required
def capture_page():
    """
    Capture page — display only.
    Start/Stop are handled by /api/capture/start and /api/capture/stop (JSON).
    The form below uses JS fetch(), not a traditional POST, so there is no
    page reload on start/stop — the UI updates instantly via the response.
    """
    running = capture_is_running()
    cached  = get_cached_devices()

    dot_cls   = "sdot-g" if running else "sdot-r"
    cap_label = "CAPTURING" if running else "STOPPED"

    ifaces     = _get_active_interfaces()
    iface_opts = "".join(f"<option value='{i}'>{i}</option>" for i in ifaces)

    cache_rows = "".join(
        f"<tr><td>{d.get('ip','')}</td><td class='mac'>{d['mac']}</td>"
        f"<td class='muted'>{_device_type_label(d.get('vendor',''), d['mac'], d.get('packet_count',0))}</td>"
        f"<td class='muted'>{_time_ago_server(d.get('last_seen',''))}</td></tr>"
        for d in cached
    )

    no_cache = '<p class="muted">No devices in cache yet.</p>'
    table = (f"<div class='tbl-wrap'><table><thead><tr><th>IP</th><th>MAC</th>"
             f"<th>Type</th><th>Last Seen</th></tr></thead>"
             f"<tbody id='cache-tbody'>{cache_rows}</tbody></table></div>"
             if cached else f'<p class="muted" id="no-cache-msg">No devices in cache yet.</p>')

    # JS handles start/stop via fetch() so the page never reloads.
    # _updateCapUI() is called immediately on button click AND by polling.
    cap_js = """<script>
var _capBusy = false;  // prevent double-click

function _updateCapUI(running){
  var dot   = document.getElementById('cap-dot');
  var lbl   = document.getElementById('cap-label');
  var btn   = document.getElementById('cap-btn');
  var iface = document.getElementById('cap-iface');
  if(dot)  { dot.className    = 'sdot ' + (running ? 'sdot-g' : 'sdot-r'); }
  if(lbl)  { lbl.textContent  = running ? 'CAPTURING' : 'STOPPED';
             lbl.className    = running ? 'c-green' : 'c-red'; }
  if(btn)  { btn.textContent  = running ? '■  STOP' : '▶  START';
             btn.className    = running ? 'btn btn-r' : 'btn btn-g';
             btn.dataset.action = running ? 'stop' : 'start';
             btn.disabled     = false; }
  if(iface){ iface.disabled       = running;
             iface.style.opacity  = running ? '0.4' : '1'; }
  _capBusy = false;
}

function toggleCapture(){
  if(_capBusy) return;
  var btn    = document.getElementById('cap-btn');
  var action = btn ? btn.dataset.action : 'start';
  var iface  = document.getElementById('cap-iface');
  var ifVal  = (iface && action === 'start') ? iface.value : '';

  // Immediately dim the button to signal the click was received
  _capBusy = true;
  if(btn) btn.disabled = true;

  fetch('/api/capture/' + action, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({interface: ifVal})
  })
  .then(function(r){ return r.json(); })
  .then(function(d){ _updateCapUI(d.running); })
  .catch(function(){
    _capBusy = false;
    if(btn) btn.disabled = false;
  });
}
</script>"""

    content = f"""
<div class="container">
  <h1>Packet Capture</h1>
  <div class="card" style="display:flex;align-items:center;gap:20px;flex-wrap:wrap">
    <div>
      <span class="sdot {dot_cls}" id="cap-dot"></span>
      <strong id="cap-label" class="{'c-green' if running else 'c-red'}">{cap_label}</strong>
    </div>
    <!-- No form POST — button calls toggleCapture() via JS fetch() -->
    <div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap">
      <div>
        <label>Interface</label>
        <select id="cap-iface"
                style="background:var(--bg);color:var(--text);border:1px solid var(--border);
                       padding:8px 12px;border-radius:4px;font-family:var(--font);
                       font-size:13px;cursor:pointer"
                {'disabled' if running else ''}>
          {iface_opts}
        </select>
      </div>
      <button id="cap-btn"
              data-action="{'stop' if running else 'start'}"
              onclick="toggleCapture()"
              class="{'btn btn-r' if running else 'btn btn-g'}">
        {'■  STOP' if running else '▶  START'}
      </button>
    </div>
  </div>
  <div class="card">
    <h2>Live Device Cache ({len(cached)})</h2>
    {table}
  </div>
</div>
{cap_js}"""
    return render_page(content, active="capture", title="Capture")


# ─────────────────────────────────────────────────────────────────────────────
# TASK 6 Feature 5: Export JSON report
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/export")
@login_required
def export_report():
    db = Database()
    report = {
        "exported_at":  datetime.utcnow().isoformat(),
        "devices":      db.get_all_devices(),
        "anomalies":    db.get_anomalies(limit=500),
        "top_active":   db.get_top_active_devices(limit=20),
        "device_types": db.get_device_types(),
        "health":       db.get_network_health(),
    }
    db.close()
    payload = json.dumps(report, indent=2, default=str)
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=pinetaid_report.json"}
    )


# ─────────────────────────────────────────────────────────────────────────────
# JSON API  (used by AJAX + external tooling)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/devices")
@login_required
def api_devices():
    db = Database()
    subnet = request.args.get("subnet", "all").strip()
    # TASK 1: "all" or missing → return everything; any specific subnet → filter
    if subnet and subnet != "all":
        data = db.get_all_devices(subnet=subnet)
    else:
        data = db.get_all_devices()
    db.close()
    return jsonify(data)


@app.route("/api/subnets")
@login_required
def api_subnets():
    """Return all known subnets. Does NOT auto-select — let the JS honour localStorage."""
    db = Database()
    subnets = db.get_subnets()
    db.close()
    # TASK 1: return subnets only, no "current" — JS should not auto-pick
    return jsonify({"subnets": subnets})


@app.route("/api/anomalies")
@login_required
def api_anomalies():
    db = Database()
    subnet = request.args.get("subnet", "").strip() or None
    data = db.get_anomalies(subnet=subnet)
    db.close()
    return jsonify(data)


@app.route("/api/clear-subnet", methods=["POST"])
@login_required
def api_clear_subnet():
    """Delete all devices and anomalies for a given subnet."""
    data   = request.get_json(silent=True) or {}
    subnet = (data.get("subnet") or "").strip()
    if not subnet or subnet == "all":
        return jsonify({"error": "No subnet specified"}), 400
    db     = Database()
    result = db.clear_subnet_data(subnet)
    db.close()
    logger.info(f"Cleared subnet {subnet}: {result}")
    return jsonify(result)


@app.route("/api/delete_subnet", methods=["POST"])
@login_required
def api_delete_subnet():
    """
    Delete all data for a subnet.
    subnet = "All"  → wipe everything from every table.
    subnet = "x.x.x.0/24" → delete only that subnet.
    """
    data   = request.get_json(silent=True) or {}
    subnet = (data.get("subnet") or "").strip()
    if not subnet:
        return jsonify({"status": "error", "message": "No subnet specified"}), 400
    db     = Database()
    result = db.delete_by_subnet(subnet)   # handles "All" internally
    db.close()
    logger.info(f"Deleted subnet={subnet!r}: {result}")
    return jsonify({"status": "ok", **result})


@app.route("/api/capture/start", methods=["POST"])
@login_required
def api_capture_start():
    """Start capture. Returns {running: true/false}."""
    if capture_is_running():
        return jsonify({"running": True, "message": "already running"})
    data  = request.get_json(silent=True) or {}
    iface = (data.get("interface") or "").strip() or None
    start_capture_thread(interface=iface)
    return jsonify({"running": capture_is_running()})


@app.route("/api/capture/stop", methods=["POST"])
@login_required
def api_capture_stop():
    """Stop capture. Blocks until thread exits, then returns {running: false}."""
    stop_capture_thread()          # joins thread before returning
    return jsonify({"running": capture_is_running(), "status": "stopped"})


@app.route("/api/status")
@login_required
def api_status():
    db = Database()
    # TASK 1: scope counts to the same subnet the UI is viewing
    subnet     = request.args.get("subnet", "").strip()
    if subnet == "all":
        subnet = ""
    health     = db.get_network_health(subnet=subnet or None)
    is_running = capture_is_running()
    data = {
        "device_count":    db.device_count(subnet=subnet or None),
        "anomaly_count":   db.anomaly_count(subnet=subnet or None),
        "capture_running": is_running,
        "running":         is_running,
        "health":          health,
    }
    db.close()
    return jsonify(data)


# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# WiFi provisioning routes — login-free, work in hotspot mode
# ─────────────────────────────────────────────────────────────────────────────


@app.route("/wifi-setup")
def wifi_setup():
    """WiFi network-selection page. Login-free — reachable from hotspot mode."""
    content = """
<div class="login-wrap">
  <div class="login-box" style="width:420px">
    <div class="login-logo">PINETAID</div>
    <div class="login-sub">WiFi Setup</div>
    <p class="muted" style="font-size:11px;text-align:center;margin-bottom:20px">
      Select your network and enter the password.<br>
      After connecting use the new IP, not 192.168.4.1.
    </p>
    <div id="wifi-msg" style="display:none;margin-bottom:14px;padding:9px 12px;
         border-radius:4px;font-size:12px"></div>
    <div class="form-group">
      <label style="display:flex;justify-content:space-between;align-items:center">
        WiFi Network
        <button id="scan-btn" onclick="doScan()" type="button"
                style="font-size:11px;padding:3px 10px;border:1px solid var(--border);
                background:var(--surface);color:var(--muted);border-radius:4px;
                cursor:pointer;font-family:var(--font)">&#8635; Scan</button>
      </label>
      <select id="ssid-sel"
              style="width:100%;margin-top:6px;padding:8px 10px;background:var(--bg);
                     color:var(--text);border:1px solid var(--border);border-radius:4px;
                     font-family:var(--font);font-size:13px">
        <option value="">Scanning...</option>
      </select>
      <input id="ssid-manual" type="text" placeholder="Type SSID here"
             style="margin-top:8px;display:none" autocomplete="off">
      <div style="margin-top:5px;font-size:11px;color:var(--muted)">
        If your network does not appear,
        <button onclick="showManual()" type="button"
                style="background:none;border:none;color:var(--blue);font-size:11px;
                cursor:pointer;font-family:var(--font);padding:0;text-decoration:underline">
          enter the SSID manually</button>.
      </div>
    </div>
    <div class="form-group">
      <label>Password</label>
      <div style="position:relative">
        <input id="wifi-pwd" type="password" placeholder="WiFi password" autocomplete="off">
        <button type="button" onclick="togglePwd()"
                style="position:absolute;right:10px;top:50%;transform:translateY(-50%);
                background:none;border:none;color:var(--muted);cursor:pointer;
                font-size:11px;font-family:var(--font)">SHOW</button>
      </div>
    </div>
    <button id="conn-btn" onclick="doConnect()" type="button"
            class="btn btn-g" style="width:100%">CONNECT</button>
    <div style="margin-top:10px;text-align:center">
      <button onclick="doStartHotspot()" type="button"
              style="background:none;border:1px solid var(--border);color:var(--muted);
              font-size:11px;padding:4px 12px;border-radius:4px;cursor:pointer;
              font-family:var(--font)">Start Setup Hotspot</button>
    </div>
    <div style="margin-top:8px;text-align:center">
      <a href="/" style="color:var(--muted);font-size:11px">Back to dashboard</a>
    </div>
  </div>
</div>"""

    content += """
<script>
(function () {
  'use strict';
  var _scanBusy = false, _connectBusy = false;

  function doScan() {
    if (_scanBusy) return;
    _scanBusy = true;
    var btn = document.getElementById('scan-btn');
    var sel = document.getElementById('ssid-sel');
    btn.textContent = '...'; btn.disabled = true;
    sel.innerHTML   = '<option value="">Scanning...</option>';
    fetch('/api/wifi/scan')
      .then(function (r) { return r.json(); })
      .then(function (d) {
        btn.textContent = '\u21bb Scan'; btn.disabled = false; _scanBusy = false;
        var nets = d.networks || [];
        if (nets.length) {
          sel.innerHTML = '<option value="">-- select network --</option>';
          nets.forEach(function (s) {
            var o = document.createElement('option');
            o.value = s; o.textContent = s; sel.appendChild(o);
          });
        } else {
          sel.innerHTML = '<option value="">No networks found</option>';
          showManual();
          showMsg('No networks found. Enter the SSID manually.', 'warn');
        }
      })
      .catch(function () {
        btn.textContent = '\u21bb Scan'; btn.disabled = false; _scanBusy = false;
        sel.innerHTML = '<option value="">Scan failed</option>';
        showManual();
        showMsg('Scan failed. Enter the SSID manually.', 'warn');
      });
  }

  window.showManual = function () {
    document.getElementById('ssid-manual').style.display = 'block';
  };
  window.togglePwd = function () {
    var i = document.getElementById('wifi-pwd');
    i.type = (i.type === 'password') ? 'text' : 'password';
  };
  window.doConnect = function () {
    if (_connectBusy) return;
    var manual = document.getElementById('ssid-manual');
    var sel    = document.getElementById('ssid-sel');
    var ssid   = (manual.style.display !== 'none' && manual.value.trim())
                  ? manual.value.trim() : sel.value.trim();
    var pwd    = document.getElementById('wifi-pwd').value;
    var btn    = document.getElementById('conn-btn');
    if (!ssid) { showMsg('Please select or enter an SSID.', 'error'); return; }
    _connectBusy = true; btn.disabled = true; btn.textContent = 'CONNECTING...';
    showMsg('Connecting to \u201c' + ssid + '\u201d\u2026 (~25 s)', 'info');
    fetch('/api/wifi/connect', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ssid: ssid, password: pwd})
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      _connectBusy = false; btn.disabled = false; btn.textContent = 'CONNECT';
      showMsg(d.message || (d.success ? 'Connected.' : 'Failed.'),
              d.success ? 'ok' : 'error');
    })
    .catch(function () {
      _connectBusy = false; btn.disabled = false; btn.textContent = 'CONNECT';
      showMsg('Pi may have switched networks. Reconnect and open its new IP.', 'warn');
    });
  };
  window.doStartHotspot = function () {
    showMsg('Starting setup hotspot...', 'info');
    fetch('/api/wifi/start-hotspot', {method: 'POST'})
      .then(function (r) { return r.json(); })
      .then(function (d) {
        showMsg(d.message || (d.success ? 'Hotspot started.' : 'Failed.'),
                d.success ? 'ok' : 'error');
      })
      .catch(function () { showMsg('Could not reach server.', 'error'); });
  };
  function showMsg(text, type) {
    var p = {
      ok:   {bg:'#1a2e1a',border:'#4caf50',   color:'#4caf50'},
      error:{bg:'#3d1f1f',border:'var(--red)', color:'var(--red)'},
      warn: {bg:'#2d2000',border:'var(--yellow)',color:'var(--yellow)'},
      info: {bg:'#1a2a3d',border:'var(--blue)', color:'var(--blue)'},
    };
    var c = p[type] || p.info;
    var el = document.getElementById('wifi-msg');
    el.style.cssText = 'display:block;background:' + c.bg
                     + ';border:1px solid ' + c.border + ';color:' + c.color;
    el.textContent = text;
  }
  doScan();
})();
</script>"""
    return render_page(content, title="WiFi Setup")


@app.route("/api/wifi/scan")
def api_wifi_scan():
    """Return visible SSIDs. No login required."""
    if not _WIFI_AVAILABLE:
        return jsonify({"networks": [], "error": "wifi_provision not installed"}), 503
    try:
        return jsonify({"networks": scan_networks()})
    except Exception as exc:
        logger.error("/api/wifi/scan: %s", exc)
        return jsonify({"networks": [], "error": str(exc)}), 500


@app.route("/api/wifi/connect", methods=["POST"])
def api_wifi_connect():
    """Write credentials and attempt a WiFi connection. No login required."""
    if not _WIFI_AVAILABLE:
        return jsonify({"success": False, "message": "wifi_provision not installed"}), 503
    try:
        data = request.get_json(silent=True) or {}
        ssid = (data.get("ssid") or "").strip()
        pwd  = data.get("password") or ""
        if not ssid:
            return jsonify({"success": False, "message": "SSID required"}), 400
        return jsonify(result := connect_to_wifi(ssid, pwd)), (200 if result.get("success") else 500)
    except Exception as exc:
        logger.error("/api/wifi/connect: %s", exc)
        return jsonify({"success": False, "message": f"Server error: {exc}"}), 500


@app.route("/api/wifi/status")
def api_wifi_status():
    """Return current network mode and IPs. No login required."""
    if not _WIFI_AVAILABLE:
        return jsonify({"mode": "unknown"})
    try:
        return jsonify(get_wifi_status())
    except Exception as exc:
        return jsonify({"mode": "unknown", "error": str(exc)}), 500


@app.route("/api/wifi/start-hotspot", methods=["POST"])
def api_wifi_start_hotspot():
    """Force the device into AP mode. No login required."""
    if not _WIFI_AVAILABLE:
        return jsonify({"success": False, "message": "wifi_provision not installed"}), 503
    try:
        enable_force_hotspot()
        result = start_hotspot()
        return jsonify(result), (200 if result.get("success") else 500)
    except Exception as exc:
        logger.error("/api/wifi/start-hotspot: %s", exc)
        return jsonify({"success": False, "message": f"Server error: {exc}"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def run_dashboard(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    run_dashboard()
