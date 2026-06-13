"""Home-network device discovery and presence tracking.

Discovery sources (best-effort, all degrade gracefully):
  * ARP table (`arp -an` / `ip neigh`) + active ping sweep to populate it
  * `arp-scan` or scapy ARP if available (faster, more reliable)
  * Reverse DNS (PTR) for hostnames
  * mDNS / Bonjour via python-zeroconf for friendly names + device types
  * Optional light TCP service fingerprint

State is persisted to ~/.netscope/devices.json so first/last-seen and uptime
survive restarts.
"""

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import psutil

import oui
import sysutil

IS_MACOS = sysutil.IS_MACOS
STATE_DIR = os.path.expanduser("~/.netscope")
STATE_FILE = os.path.join(STATE_DIR, "devices.json")
ONLINE_WINDOW = 90          # seconds since last_seen to count as "online"
FINGERPRINT_PORTS = {
    22: "ssh", 80: "http", 443: "https", 445: "smb", 139: "netbios",
    548: "afp", 554: "rtsp/camera", 631: "ipp/printer", 9100: "raw/printer",
    5000: "upnp", 8009: "chromecast", 62078: "iphone-sync", 1883: "mqtt",
    32400: "plex", 8123: "home-assistant", 53: "dns", 3389: "rdp",
}

# mDNS service type -> friendly device kind
MDNS_KIND = {
    "_airplay._tcp": "Apple TV / AirPlay", "_raop._tcp": "AirPlay speaker",
    "_googlecast._tcp": "Chromecast / Google", "_spotify-connect._tcp": "Speaker",
    "_ipp._tcp": "Printer", "_ipps._tcp": "Printer", "_pdl-datastream._tcp": "Printer",
    "_printer._tcp": "Printer", "_homekit._tcp": "HomeKit device",
    "_hap._tcp": "HomeKit device", "_sonos._tcp": "Sonos speaker",
    "_smb._tcp": "File server / NAS", "_afpovertcp._tcp": "Mac / NAS",
    "_ssh._tcp": "Computer", "_workstation._tcp": "Computer",
    "_companion-link._tcp": "Apple device", "_amzn-wplay._tcp": "Amazon device",
    "_googlezone._tcp": "Google device", "_hue._tcp": "Philips Hue",
}


def _run(cmd, timeout=8):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              **sysutil.no_window_kwargs()).stdout
    except Exception:
        return ""


def local_networks():
    """Return list of (iface, ip, ipaddress.ip_network) for active IPv4 LANs."""
    nets = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for iface, alist in addrs.items():
        st = stats.get(iface)
        if not st or not st.isup:
            continue
        for a in alist:
            if a.family == socket.AF_INET and a.netmask and not a.address.startswith("127."):
                try:
                    net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
                    if net.num_addresses <= 4096:   # don't sweep huge ranges
                        nets.append((iface, a.address, net))
                except Exception:
                    pass
    return nets


def read_arp_table():
    """Return dict ip -> mac from the OS ARP cache.

    Handles both POSIX (`arp -an` / `ip neigh`, colon-separated MACs) and
    Windows (`arp -a`, dash-separated MACs). Broadcast/multicast pseudo-entries
    are skipped so they don't show up as phantom devices.
    """
    out = {}
    text = _run(sysutil.arp_table_cmd()) or _run(["ip", "neigh"])
    for line in text.splitlines():
        ipm = re.search(r"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?", line)
        # MAC with either ':' (POSIX) or '-' (Windows) separators
        macm = re.search(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", line)
        if ipm and macm:
            octets = re.split(r"[:-]", macm.group(1))
            mac = ":".join(f"{int(x, 16):02x}" for x in octets)
            if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                continue
            if mac.startswith(("01:00:5e", "33:33")):   # IPv4/IPv6 multicast
                continue
            out[ipm.group(1)] = mac.lower()
    return out


def ping_sweep(net, workers=128):
    """Ping every host to populate the ARP cache. Best-effort, ignores failures."""
    def ping(ip):
        try:
            subprocess.run(sysutil.ping_args(ip), capture_output=True, timeout=2,
                           **sysutil.no_window_kwargs())
        except Exception:
            pass

    hosts = list(net.hosts())
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(ping, hosts))


def arp_scan_tool(iface):
    """Use the `arp-scan` utility if installed (fast + reliable). ip->mac."""
    if not shutil.which("arp-scan"):
        return {}
    out = _run(["arp-scan", "--localnet", "-I", iface, "-q"], timeout=25)
    res = {}
    for line in out.splitlines():
        m = re.match(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:]{17})", line)
        if m:
            res[m.group(1)] = m.group(2).lower()
    return res


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def fingerprint(ip, ports=None, timeout=0.4):
    """Light TCP connect scan -> list of open service names."""
    found = []
    for port, name in (ports or FINGERPRINT_PORTS).items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                found.append(name)
        except Exception:
            pass
        finally:
            s.close()
    return found


def guess_kind(dev):
    """Infer a device type from vendor, services, mDNS, hostname."""
    services = set(dev.get("services") or [])
    mdns = set(dev.get("mdns_types") or [])
    vendor = (dev.get("vendor") or "").lower()
    name = (dev.get("name") or dev.get("hostname") or "").lower()

    for t, kind in MDNS_KIND.items():
        if t in mdns:
            return kind
    if any(p in services for p in ("ipp/printer", "raw/printer")):
        return "Printer"
    if "rtsp/camera" in services:
        return "Camera"
    if "iphone-sync" in services or "iphone" in name:
        return "iPhone"
    if "chromecast" in services:
        return "Chromecast"
    if "plex" in services or "home-assistant" in services:
        return "Media/Home server"
    if "espressif" in vendor or "iot" in vendor or "tuya" in vendor or "shelly" in vendor:
        return "Smart-home / IoT"
    if "raspberry" in vendor:
        return "Raspberry Pi"
    if vendor in ("ubiquiti", "tp-link", "netgear", "asus"):
        return "Router / AP"
    if "apple" in vendor:
        return "Apple device"
    if "samsung" in vendor or "lg" in vendor or "sony" in vendor or "roku" in vendor:
        return "TV / Media"
    if "sonos" in vendor:
        return "Speaker"
    if any(s in services for s in ("ssh", "smb", "afp")):
        return "Computer"
    return "Device"


class MDNSBrowser:
    """Passively learns device names + service types via zeroconf, if installed."""

    def __init__(self):
        self.records = {}            # ip -> {"name": str, "types": set()}
        self.lock = threading.Lock()
        self.ok = False
        try:
            from zeroconf import Zeroconf, ServiceBrowser  # noqa
            self._zc_mod = __import__("zeroconf")
            self.ok = True
        except Exception:
            self.ok = False

    def start(self):
        if not self.ok:
            return
        try:
            from zeroconf import Zeroconf, ServiceBrowser, ServiceListener

            browser_self = self

            class _L(ServiceListener):
                def _store(self, zc, type_, name):
                    try:
                        info = zc.get_service_info(type_, name, timeout=1500)
                        if not info:
                            return
                        for addr in info.parsed_addresses():
                            with browser_self.lock:
                                rec = browser_self.records.setdefault(
                                    addr, {"name": None, "types": set()})
                                base = type_.replace(".local.", "").rstrip(".")
                                rec["types"].add(base)
                                friendly = name.split("." + type_)[0]
                                if friendly and not rec["name"]:
                                    rec["name"] = friendly
                    except Exception:
                        pass

                def add_service(self, zc, type_, name): self._store(zc, type_, name)
                def update_service(self, zc, type_, name): self._store(zc, type_, name)
                def remove_service(self, zc, type_, name): pass

            zc = Zeroconf()
            types = list(MDNS_KIND.keys()) + ["_device-info._tcp"]
            for t in types:
                try:
                    ServiceBrowser(zc, t + ".local.", _L())
                except Exception:
                    pass
        except Exception:
            self.ok = False

    def for_ip(self, ip):
        with self.lock:
            r = self.records.get(ip)
            if not r:
                return None, []
            return r["name"], sorted(r["types"])


class DeviceTracker:
    def __init__(self, do_fingerprint=True):
        self.devices = {}            # mac -> device dict
        self.by_ip = {}              # ip -> mac
        self.lock = threading.Lock()
        self.do_fingerprint = do_fingerprint
        self.last_scan = 0
        self.scan_count = 0
        self.mdns = MDNSBrowser()
        self._load()

    # ---- persistence ----
    def _load(self):
        try:
            with open(STATE_FILE) as fh:
                data = json.load(fh)
            for d in data.get("devices", []):
                self.devices[d["mac"]] = d
        except Exception:
            pass

    def _save(self):
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with self.lock:
                snap = {"devices": list(self.devices.values())}
            tmp = STATE_FILE + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(snap, fh)
            os.replace(tmp, STATE_FILE)
        except Exception:
            pass

    def start(self):
        self.mdns.start()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                self.scan_once()
            except Exception:
                pass
            self._save()
            time.sleep(45)

    def scan_once(self):
        nets = local_networks()
        seen = {}                    # ip -> mac
        for iface, ip, net in nets:
            seen.update(arp_scan_tool(iface))
            ping_sweep(net)
        seen.update(read_arp_table())
        now = time.time()

        with self.lock:
            for ip, mac in seen.items():
                dev = self.devices.get(mac)
                if not dev:
                    dev = {
                        "mac": mac, "ip": ip, "first_seen": now,
                        "vendor": oui.lookup(mac),
                        "random_mac": oui.is_locally_administered(mac),
                        "name": None, "hostname": None, "kind": None,
                        "services": [], "mdns_types": [],
                        "seen_count": 0,
                    }
                    self.devices[mac] = dev
                dev["ip"] = ip
                dev["last_seen"] = now
                dev["seen_count"] = dev.get("seen_count", 0) + 1
                if not dev.get("vendor"):
                    dev["vendor"] = oui.lookup(mac)
                self.by_ip[ip] = mac

        # enrichment (outside the byte-counting hot path)
        for mac, dev in list(self.devices.items()):
            ip = dev.get("ip")
            if not ip or dev.get("last_seen", 0) < now - ONLINE_WINDOW:
                continue
            if not dev.get("hostname"):
                dev["hostname"] = reverse_dns(ip)
            mname, mtypes = self.mdns.for_ip(ip)
            if mname:
                dev["name"] = mname
            if mtypes:
                dev["mdns_types"] = mtypes
            if self.do_fingerprint and dev.get("seen_count", 0) <= 2:
                dev["services"] = fingerprint(ip)
            dev["kind"] = guess_kind(dev)

        self.last_scan = now
        self.scan_count += 1

    def display_name(self, dev):
        if dev.get("name"):
            return dev["name"]
        if dev.get("hostname"):
            return dev["hostname"]
        if dev.get("vendor"):
            return f"{dev['vendor']} device"
        # No name/hostname/vendor: identify by the MAC tail rather than a
        # useless "Unknown device". Randomized/private MACs (phones, privacy
        # mode) can't have a vendor by design, so label them as such.
        mac = (dev.get("mac") or "").replace(":", "")
        if len(mac) >= 6:
            tail = mac[-6:]
            label = f"{tail[0:2]}:{tail[2:4]}:{tail[4:6]}"
            if dev.get("random_mac"):
                return f"Private device ({label})"
            return f"Device {label}"
        return f"Device {dev.get('ip') or '?'}"

    def snapshot(self):
        now = time.time()
        with self.lock:
            devs = list(self.devices.values())
        out = []
        online = 0
        for d in devs:
            is_online = (now - d.get("last_seen", 0)) <= ONLINE_WINDOW
            if is_online:
                online += 1
            uptime = (d.get("last_seen", now) - d.get("first_seen", now))
            out.append({
                **d,
                "display_name": self.display_name(d),
                "online": is_online,
                "last_seen_ago": int(now - d.get("last_seen", now)),
                "tracked_for": int(uptime),
            })
        out.sort(key=lambda d: (not d["online"], d.get("ip") or ""))
        return {
            "devices": out,
            "total": len(out),
            "online": online,
            "scan_count": self.scan_count,
            "last_scan_ago": int(now - self.last_scan) if self.last_scan else None,
            "networks": [str(n) for _, _, n in local_networks()],
            "mdns": self.mdns.ok,
        }

    def ip_to_label(self):
        """Map ip -> friendly label for the capture engine."""
        with self.lock:
            return {d["ip"]: (self.display_name(d), d.get("kind"), d.get("vendor"))
                    for d in self.devices.values() if d.get("ip")}
