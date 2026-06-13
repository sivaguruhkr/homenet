"""Domain intelligence + DNS firewall.

Pieces:
  * Blocklist      — persisted set of blocked domains (exact + wildcard suffix)
  * DomainIntel    — correlates DNS queries/answers to map remote IP <-> domain,
                     tracks per-device domains and per-domain traffic
  * DNSWatch       — passive tcpdump on port 53; feeds DomainIntel and a query log,
                     flags queries to blocked domains
  * Sinkhole       — OPTIONAL active DNS server (needs `dnslib`, root, port 53):
                     forwards to an upstream resolver but answers blocked domains
                     with NXDOMAIN. This is what actually enforces domain blocking
                     across the home network (point your router's DHCP DNS at this
                     machine, exactly like Pi-hole / AdGuard Home).
"""

import json
import os
import re
import socket
import subprocess
import threading
import time
from collections import Counter, defaultdict, deque

import sysutil

STATE_DIR = os.path.expanduser("~/.netscope")
BLOCK_FILE = os.path.join(STATE_DIR, "blocked_domains.json")

DOMAIN_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def valid_domain(d):
    return bool(d) and len(d) <= 253 and bool(DOMAIN_RE.match(d))


class Blocklist:
    def __init__(self):
        self.lock = threading.Lock()
        self.exact = set()
        self.load()

    def load(self):
        try:
            with open(BLOCK_FILE) as fh:
                for d in json.load(fh).get("domains", []):
                    self.exact.add(d.lower().strip("."))
        except Exception:
            pass

    def save(self):
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with self.lock:
                data = {"domains": sorted(self.exact)}
            with open(BLOCK_FILE + ".tmp", "w") as fh:
                json.dump(data, fh)
            os.replace(BLOCK_FILE + ".tmp", BLOCK_FILE)
        except Exception:
            pass

    def block(self, domain):
        domain = (domain or "").lower().strip().strip(".")
        if not valid_domain(domain):
            return False
        with self.lock:
            self.exact.add(domain)
        self.save()
        return True

    def unblock(self, domain):
        domain = (domain or "").lower().strip().strip(".")
        with self.lock:
            self.exact.discard(domain)
        self.save()
        return True

    def is_blocked(self, name):
        name = (name or "").lower().strip(".")
        if not name:
            return False
        with self.lock:
            if name in self.exact:
                return True
            # suffix match: blocking example.com also blocks ads.example.com
            parts = name.split(".")
            for i in range(len(parts) - 1):
                if ".".join(parts[i:]) in self.exact:
                    return True
        return False

    def list(self):
        with self.lock:
            return sorted(self.exact)


class DomainIntel:
    def __init__(self):
        self.lock = threading.Lock()
        self.ip_domain = {}                       # remote ip -> domain
        self.domain_ips = defaultdict(set)        # domain -> {ips}
        self.domain_bytes = Counter()             # domain -> bytes seen
        self.domain_devices = defaultdict(set)    # domain -> {device ips}
        self.device_domains = defaultdict(Counter)  # device ip -> Counter(domain)->queries

    def learn(self, domain, ips, client=None):
        domain = (domain or "").lower().strip(".")
        if not domain:
            return
        with self.lock:
            for ip in ips:
                self.ip_domain[ip] = domain
                self.domain_ips[domain].add(ip)
            if client:
                self.device_domains[client][domain] += 1
                self.domain_devices[domain].add(client)

    def domain_for_ip(self, ip):
        with self.lock:
            return self.ip_domain.get(ip)

    def add_traffic(self, ip, nbytes, device_ip=None):
        with self.lock:
            d = self.ip_domain.get(ip)
            if d:
                self.domain_bytes[d] += nbytes
                if device_ip:
                    self.domain_devices[d].add(device_ip)

    def top_domains(self, n=20):
        with self.lock:
            return [{"domain": d, "bytes": b,
                     "devices": len(self.domain_devices.get(d, ()))}
                    for d, b in self.domain_bytes.most_common(n)]

    def domains_for_device(self, device_ip, n=30):
        with self.lock:
            return self.device_domains.get(device_ip, Counter()).most_common(n)


class DNSWatch:
    """Passive DNS capture -> domain intel + query log."""

    QUERY_RE = re.compile(
        r":\s+(\d+)[+*\-\s]?\s*(?:\[[^\]]*\]\s*)?"
        r"(A|AAAA|CNAME|MX|TXT|NS|PTR|SOA|SRV|HTTPS|SVCB)\?\s+([^\s,]+?)\.?[\s,]")
    ANSWER_A_RE = re.compile(r"\bA{1,4}\s+(\d{1,3}(?:\.\d{1,3}){3})")
    ID_RE = re.compile(r":\s+(\d+)\s")
    PAIR_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s+>\s+(\d{1,3}(?:\.\d{1,3}){3})\.(\d+):")

    def __init__(self, intel, blocklist, history=300):
        self.intel = intel
        self.blocklist = blocklist
        self.tool = sysutil.capture_tool()
        self.available = self.tool is not None
        self.reason = self._reason()
        self.events = deque(maxlen=history)
        self.qtypes = Counter()
        self.clients = Counter()                   # client ip -> query count
        self.blocked_hits = Counter()             # domain -> count seen being queried
        self.pending = {}                          # id -> (domain, client, t)
        self.lock = threading.Lock()
        self.total = 0

    def _reason(self):
        if not self.tool:
            return ("tcpdump missing" if not sysutil.IS_WINDOWS
                    else "WinDump/tcpdump missing (install Npcap + WinDump)")
        if not sysutil.is_admin():
            return f"{sysutil.admin_hint()} for DNS capture"
        return "active"

    def start(self):
        if not self.available or not sysutil.is_admin():
            return
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        import discovery
        nets = discovery.local_networks()
        iface = nets[0][0] if nets else None
        cmd = [self.tool, "-l", "-n", "-tt"]
        if iface:
            cmd += ["-i", iface]
        cmd += ["port", "53"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except Exception as e:
            self.available = False
            self.reason = f"{self.tool} failed: {e}"
            return
        for line in proc.stdout:
            try:
                self.feed_line(line)
            except Exception:
                pass

    def _client_of(self, line):
        m = self.PAIR_RE.search(line)
        if not m:
            return None
        sip, sport, dip, dport = m.group(1), m.group(2), m.group(3), m.group(4)
        # the side whose port is not 53 is the asking device
        if dport == "53":
            return sip
        if sport == "53":
            return dip
        return sip

    def feed_line(self, line):
        client = self._client_of(line)
        qm = self.QUERY_RE.search(line)
        if qm:
            qid, qtype, domain = qm.group(1), qm.group(2), qm.group(3).lower()
            blocked = self.blocklist.is_blocked(domain)
            with self.lock:
                self.total += 1
                self.qtypes[qtype] += 1
                if client:
                    self.clients[client] += 1
                self.pending[qid] = (domain, client, time.time())
                if len(self.pending) > 4000:
                    self.pending.clear()
                if blocked:
                    self.blocked_hits[domain] += 1
                self.events.appendleft({"t": time.time(), "qtype": qtype,
                                        "domain": domain, "client": client,
                                        "blocked": blocked})
            return
        # answer line -> map answer IPs to the pending query's domain
        idm = self.ID_RE.search(line)
        if idm:
            qid = idm.group(1)
            ips = self.ANSWER_A_RE.findall(line)
            with self.lock:
                pend = self.pending.get(qid)
            if pend and ips:
                domain, qclient, _ = pend
                self.intel.learn(domain, ips, qclient or client)

    def snapshot(self):
        with self.lock:
            return {
                "available": self.available, "reason": self.reason,
                "events": list(self.events)[:120],
                "qtypes": self.qtypes.most_common(),
                "by_client": self.clients.most_common(15),
                "blocked_hits": self.blocked_hits.most_common(15),
                "total": self.total,
            }


class Sinkhole:
    """Optional active DNS server enforcing the blocklist (Pi-hole style)."""

    def __init__(self, blocklist, cfg, dnswatch=None):
        cfg = cfg or {}
        self.blocklist = blocklist
        self.dnswatch = dnswatch
        self.enabled = bool(cfg.get("enabled"))
        self.upstream = cfg.get("upstream", "1.1.1.1")
        self.port = int(cfg.get("port", 53))
        self.blocked_served = Counter()           # domain -> times sinkholed
        self.served = 0
        self.lock = threading.Lock()
        try:
            import dnslib  # noqa
            self.have_lib = True
        except Exception:
            self.have_lib = False
        self.status = self._status()

    def _status(self):
        if not self.enabled:
            return "disabled"
        if not self.have_lib:
            return "needs: pip install dnslib"
        if not sysutil.is_admin() and self.port < 1024:
            return f"{sysutil.admin_hint()} to bind port {self.port}"
        return "active"

    def start(self):
        if self.status != "active":
            return
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        from dnslib import DNSRecord, RR, QTYPE, RCODE
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", self.port))
        except Exception as e:
            self.status = f"bind failed: {e}"
            return
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                req = DNSRecord.parse(data)
                qname = str(req.q.qname).rstrip(".")
                with self.lock:
                    self.served += 1
                if self.blocklist.is_blocked(qname):
                    with self.lock:
                        self.blocked_served[qname] += 1
                    reply = req.reply()
                    reply.header.rcode = RCODE.NXDOMAIN
                    sock.sendto(reply.pack(), addr)
                    continue
                # forward to upstream
                try:
                    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    up.settimeout(3)
                    up.sendto(data, (self.upstream, 53))
                    resp, _ = up.recvfrom(4096)
                    sock.sendto(resp, addr)
                    up.close()
                except Exception:
                    pass
            except Exception:
                continue

    def snapshot(self):
        with self.lock:
            return {"enabled": self.enabled, "status": self.status,
                    "upstream": self.upstream, "served": self.served,
                    "blocked_served": self.blocked_served.most_common(15)}
