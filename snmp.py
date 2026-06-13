"""Optional SNMP poller.

The legitimate route to COMPLETE per-device / per-port byte accounting is the
network gear itself. If your router or managed switch speaks SNMP, point this at
it and it will poll IF-MIB interface counters (per physical/virtual port) and
turn them into live rates.

Uses the system `snmpwalk`/`snmpget` tools (net-snmp) so there's no heavy Python
dependency. Install net-snmp:  `brew install net-snmp`.

Configure via config.json:
    {
      "snmp": {
        "enabled": true,
        "host": "192.168.1.1",
        "community": "public",
        "version": "2c"
      }
    }
"""

import re
import shutil
import subprocess
import threading
import time

import sysutil

OID_IFDESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IN_HC = "1.3.6.1.2.1.31.1.1.1.6"      # ifHCInOctets (64-bit)
OID_OUT_HC = "1.3.6.1.2.1.31.1.1.1.10"    # ifHCOutOctets
OID_IN_32 = "1.3.6.1.2.1.2.2.1.10"        # ifInOctets fallback
OID_OUT_32 = "1.3.6.1.2.1.2.2.1.16"       # ifOutOctets fallback


class SNMPPoller:
    def __init__(self, cfg):
        cfg = cfg or {}
        self.enabled = bool(cfg.get("enabled"))
        self.host = cfg.get("host")
        self.community = cfg.get("community", "public")
        self.version = str(cfg.get("version", "2c"))
        self.have_tools = shutil.which("snmpwalk") is not None
        self.lock = threading.Lock()
        self.ports = {}              # ifIndex -> {name, in, out, in_bps, out_bps}
        self.prev = {}
        self.prev_t = time.time()
        self.status = self._status()

    def _status(self):
        if not self.enabled:
            return "disabled"
        if not self.have_tools:
            if sysutil.IS_WINDOWS:
                hint = "install Net-SNMP and add it to PATH"
            elif sysutil.IS_MACOS:
                hint = "brew install net-snmp"
            else:
                hint = "apt install snmp"
            return f"net-snmp tools not installed ({hint})"
        if not self.host:
            return "no host configured"
        return "active"

    def _walk(self, oid):
        cmd = ["snmpwalk", f"-v{self.version}", "-c", self.community,
               "-Oqn", "-t", "2", "-r", "1", self.host, oid]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                                 **sysutil.no_window_kwargs()).stdout
        except Exception:
            return {}
        res = {}
        for line in out.splitlines():
            m = re.match(rf"\.?{re.escape(oid)}\.(\d+)\s+(.*)", line.strip())
            if m:
                res[int(m.group(1))] = m.group(2).strip().strip('"')
        return res

    def start(self):
        if self.status != "active":
            return
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                self._poll()
            except Exception as e:
                self.status = f"error: {e}"
            time.sleep(2.0)

    def _poll(self):
        names = self._walk(OID_IFDESCR)
        ins = self._walk(OID_IN_HC) or self._walk(OID_IN_32)
        outs = self._walk(OID_OUT_HC) or self._walk(OID_OUT_32)
        now = time.time()
        dt = max(now - self.prev_t, 1e-6)
        ports = {}
        for idx, name in names.items():
            try:
                cin = int(ins.get(idx, 0)); cout = int(outs.get(idx, 0))
            except ValueError:
                continue
            pin, pout = self.prev.get(idx, (cin, cout))
            ports[idx] = {
                "index": idx, "name": name,
                "in": cin, "out": cout,
                "in_bps": max(cin - pin, 0) / dt,
                "out_bps": max(cout - pout, 0) / dt,
            }
            self.prev[idx] = (cin, cout)
        self.prev_t = now
        with self.lock:
            self.ports = ports
        self.status = "active"

    def snapshot(self):
        with self.lock:
            ports = sorted(self.ports.values(),
                           key=lambda p: p["in_bps"] + p["out_bps"], reverse=True)
        return {"enabled": self.enabled, "status": self.status,
                "host": self.host, "ports": ports}
