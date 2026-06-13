"""Per-device passive traffic accounting via tcpdump (enhanced).

Attributes bytes/packets to local devices and now also tracks, per device:
  * top remote destinations (labeled with domain via DomainIntel)
  * active connections (proto + remote ip:port + bytes)
  * a short per-device rate timeline (for the drill-down graph)
  * per-protocol byte mix

Coverage honesty unchanged: on a switched network a host only receives its own
unicast plus broadcast/multicast, so totals are complete only when this machine
is the gateway / on a hub / on a mirrored (SPAN) switch port. The dashboard
reports how many devices are actually seen on the wire.
"""

import ipaddress
import re
import subprocess
import threading
import time
from collections import defaultdict, deque, Counter

import sysutil

LINE_RE = re.compile(
    r"^(?P<ts>\d+\.\d+)\s+"
    r"(?P<smac>[0-9a-fA-F:]{17})\s+>\s+(?P<dmac>[0-9a-fA-F:]{17}),.*?"
    r"length\s+(?P<len>\d+):\s+"
    r"(?P<rest>.*)$")
IP_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})(?:\.(\d+))?\s+>\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\.(\d+))?")
PROTO_RE = re.compile(r"\b(tcp|udp|icmp|igmp)\b", re.I)

PORT_PROTO = {
    443: "HTTPS", 80: "HTTP", 53: "DNS", 853: "DoT", 123: "NTP", 22: "SSH",
    5353: "mDNS", 1900: "SSDP", 67: "DHCP", 68: "DHCP", 993: "IMAPS",
    587: "SMTP", 3478: "STUN/RTC", 5060: "SIP", 32400: "Plex", 1883: "MQTT",
    8009: "Cast", 554: "RTSP", 3389: "RDP", 445: "SMB",
}


def classify(rest):
    for p in re.findall(r"\.(\d+)\s", rest):
        try:
            if int(p) in PORT_PROTO:
                return PORT_PROTO[int(p)]
        except ValueError:
            pass
    m = PROTO_RE.search(rest)
    if m:
        return m.group(1).upper()
    if "ARP" in rest:
        return "ARP"
    return "other"


class DeviceCounters:
    def __init__(self):
        self.rx = self.tx = self.pkts = 0
        self.prev_rx = self.prev_tx = 0
        self.rx_bps = self.tx_bps = 0.0
        self.protos = defaultdict(int)
        self.dests = Counter()                 # remote ip -> bytes
        self.conns = {}                        # (proto,rip,rport) -> {bytes,last}
        self.timeline = deque(maxlen=60)       # {t, rx_bps, tx_bps}
        self.last = 0.0


class CaptureEngine:
    def __init__(self, tracker, intel=None):
        self.tracker = tracker
        self.intel = intel
        self.tool = sysutil.capture_tool()
        self.available = self.tool is not None
        self.reason = self._reason()
        self.counters = defaultdict(DeviceCounters)
        self.lock = threading.Lock()
        self.local_nets = []
        self.prev_t = time.time()
        self.total_bytes = 0
        self.seen_ips = set()
        self.global_dests = Counter()

    def _reason(self):
        if not self.tool:
            return ("tcpdump not found." if not sysutil.IS_WINDOWS
                    else "WinDump/tcpdump not found (install Npcap + WinDump).")
        if not sysutil.is_admin():
            return f"{sysutil.admin_hint().capitalize()} to capture per-device traffic."
        return "active"

    def _iface(self):
        from discovery import local_networks
        nets = local_networks()
        self.local_nets = [n for _, _, n in nets]
        return nets[0][0] if nets else None

    def _is_local(self, ip):
        try:
            a = ipaddress.ip_address(ip)
            return any(a in n for n in self.local_nets)
        except Exception:
            return False

    def start(self):
        if not self.available or not sysutil.is_admin():
            return
        threading.Thread(target=self._run, daemon=True).start()
        threading.Thread(target=self._rate_loop, daemon=True).start()

    def _run(self):
        iface = self._iface()
        cmd = [self.tool, "-n", "-e", "-tt", "-l", "-q"]
        if iface:
            cmd += ["-i", iface]
        cmd += ["ip", "or", "ip6", "or", "arp"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except Exception as e:
            self.reason = f"{self.tool} failed: {e}"
            self.available = False
            return
        for line in proc.stdout:
            try:
                self._parse(line)
            except Exception:
                pass

    def _account(self, dev_ip, remote_ip, rport, proto, length, direction):
        c = self.counters[dev_ip]
        if direction == "tx":
            c.tx += length
        else:
            c.rx += length
        c.pkts += 1
        c.protos[proto] += length
        c.last = time.time()
        if remote_ip and not self._is_local(remote_ip):
            c.dests[remote_ip] += length
            self.global_dests[remote_ip] += length
            key = (proto, remote_ip, rport)
            conn = c.conns.get(key)
            if not conn:
                conn = {"bytes": 0, "last": 0}
                if len(c.conns) < 400:
                    c.conns[key] = conn
            conn["bytes"] += length
            conn["last"] = time.time()
            if self.intel:
                self.intel.add_traffic(remote_ip, length, dev_ip)
        self.seen_ips.add(dev_ip)

    def _parse(self, line):
        m = LINE_RE.match(line.strip())
        if not m:
            return
        length = int(m.group("len"))
        rest = m.group("rest")
        ipm = IP_RE.search(rest)
        if not ipm:
            return
        src, sport, dst, dport = ipm.group(1), ipm.group(2), ipm.group(3), ipm.group(4)
        proto = classify(rest)
        with self.lock:
            self.total_bytes += length
            if self._is_local(src):
                self._account(src, dst, dport, proto, length, "tx")
            if self._is_local(dst):
                self._account(dst, src, sport, proto, length, "rx")

    def _rate_loop(self):
        while True:
            time.sleep(1.0)
            now = time.time()
            dt = max(now - self.prev_t, 1e-6)
            with self.lock:
                for c in self.counters.values():
                    c.rx_bps = max(c.rx - c.prev_rx, 0) / dt
                    c.tx_bps = max(c.tx - c.prev_tx, 0) / dt
                    c.prev_rx, c.prev_tx = c.rx, c.tx
                    c.timeline.append({"t": now, "rx_bps": c.rx_bps, "tx_bps": c.tx_bps})
            self.prev_t = now

    def _label(self, ip):
        dom = self.intel.domain_for_ip(ip) if self.intel else None
        return dom or ip

    def snapshot(self):
        labels = self.tracker.ip_to_label()
        with self.lock:
            rows = []
            for ip, c in self.counters.items():
                name, kind, vendor = labels.get(ip, (ip, None, None))
                top = sorted(c.protos.items(), key=lambda kv: kv[1], reverse=True)[:5]
                rows.append({
                    "ip": ip, "name": name, "kind": kind, "vendor": vendor,
                    "rx": c.rx, "tx": c.tx, "pkts": c.pkts,
                    "rx_bps": c.rx_bps, "tx_bps": c.tx_bps,
                    "total_bps": c.rx_bps + c.tx_bps, "protocols": top,
                })
            seen = len(self.seen_ips)
            total = self.total_bytes
            gdest = self.global_dests.most_common(20)
        rows.sort(key=lambda r: r["rx"] + r["tx"], reverse=True)
        return {
            "available": self.available, "reason": self.reason,
            "devices": rows, "devices_seen_on_wire": seen, "total_bytes": total,
            "top_destinations": [{"endpoint": self._label(ip), "ip": ip, "bytes": b}
                                 for ip, b in gdest],
        }

    def device_detail(self, ip):
        with self.lock:
            c = self.counters.get(ip)
            if not c:
                return None
            dests = [{"endpoint": self._label(d), "ip": d, "bytes": b}
                     for d, b in c.dests.most_common(15)]
            conns = sorted(c.conns.items(), key=lambda kv: kv[1]["bytes"], reverse=True)[:25]
            conn_rows = [{"proto": k[0], "endpoint": self._label(k[1]), "ip": k[1],
                          "port": k[2], "bytes": v["bytes"]} for k, v in conns]
            protos = sorted(c.protos.items(), key=lambda kv: kv[1], reverse=True)
            timeline = list(c.timeline)
            rx, tx = c.rx, c.tx
        domains = self.intel.domains_for_device(ip) if self.intel else []
        return {"ip": ip, "rx": rx, "tx": tx, "destinations": dests,
                "connections": conn_rows, "protocols": protos,
                "timeline": timeline,
                "domains": [{"domain": d, "queries": n} for d, n in domains]}
