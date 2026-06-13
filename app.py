#!/usr/bin/env python3
"""HomeScope — whole-home network monitor (extended).

Adds to the core discovery/presence/capture:
  * Domain intelligence (IP<->domain) + per-device domains  (resolver.py)
  * Domain firewall: DNS sinkhole blocking (resolver.py)
  * Packet-filter firewall: pf IP blocking, opt-in           (firewall.py)
  * Alerts: new device / bandwidth / blocked hits            (alerts.py)
  * Per-device drill-down + CSV/JSON export

Run:  python app.py    (core)   |   sudo python app.py   (capture+DNS+pf)
Open: http://127.0.0.1:8788
"""

import asyncio
import csv
import io
import json
import os
import socket
import sys
import threading
import time

import psutil
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Body
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from collections import deque

import discovery
import capture
import resolver as resolver_mod
import firewall as firewall_mod
import alerts as alerts_mod
import snmp as snmp_mod
import sysutil

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = os.environ.get("HOMESCOPE_HOST", "127.0.0.1")
PORT = int(os.environ.get("HOMESCOPE_PORT", "8788"))
IS_ROOT = sysutil.is_admin()


def load_config():
    try:
        with open(os.path.join(HERE, "config.json")) as fh:
            return json.load(fh)
    except Exception:
        return {}


CONFIG = load_config()


class LocalBandwidth:
    def __init__(self, history=120):
        self.prev = psutil.net_io_counters()
        self.prev_t = time.time()
        self.timeline = deque(maxlen=history)
        self.lock = threading.Lock()

    def sample(self):
        cur = psutil.net_io_counters()
        t = time.time()
        dt = max(t - self.prev_t, 1e-6)
        rx = max(cur.bytes_recv - self.prev.bytes_recv, 0) / dt
        tx = max(cur.bytes_sent - self.prev.bytes_sent, 0) / dt
        self.prev, self.prev_t = cur, t
        with self.lock:
            self.timeline.append({"t": t, "rx": rx, "tx": tx})

    def snapshot(self):
        with self.lock:
            tl = list(self.timeline)
        return {"timeline": tl, "current": tl[-1] if tl else {"rx": 0, "tx": 0}}


# wire modules
tracker = discovery.DeviceTracker(do_fingerprint=CONFIG.get("fingerprint", True))
blocklist = resolver_mod.Blocklist()
intel = resolver_mod.DomainIntel()
dnswatch = resolver_mod.DNSWatch(intel, blocklist)
sinkhole = resolver_mod.Sinkhole(blocklist, CONFIG.get("sinkhole"), dnswatch)
cap = capture.CaptureEngine(tracker, intel)
firewall = firewall_mod.make_firewall(CONFIG.get("firewall"))
alerts = alerts_mod.AlertEngine(CONFIG.get("alerts"))
snmp = snmp_mod.SNMPPoller(CONFIG.get("snmp"))
localbw = LocalBandwidth()

_state_lock = threading.Lock()
_latest = {}


def host_facts():
    return {"hostname": socket.gethostname(), "is_root": IS_ROOT,
            "platform": sys.platform, "cpu_percent": psutil.cpu_percent(interval=None)}


def sampler_loop():
    psutil.cpu_percent(interval=None)
    while True:
        start = time.time()
        try:
            localbw.sample()
            devices = tracker.snapshot()
            traffic = cap.snapshot()
            dns = dnswatch.snapshot()
            alerts.evaluate(devices, traffic, dns)
            state = {
                "ts": time.time(), "host": host_facts(),
                "devices": devices, "traffic": traffic, "dns": dns,
                "domains": {"top": intel.top_domains(20)},
                "blocklist": blocklist.list(),
                "sinkhole": sinkhole.snapshot(),
                "firewall": firewall.status(),
                "alerts": alerts.snapshot(),
                "snmp": snmp.snapshot(),
                "localbw": localbw.snapshot(),
                "capabilities": {
                    "root": IS_ROOT,
                    "capture": cap.available and IS_ROOT,
                    "capture_reason": cap.reason,
                    "dns": dnswatch.available,
                    "dns_reason": dnswatch.reason,
                    "mdns": tracker.mdns.ok,
                    "sinkhole": sinkhole.status,
                    "firewall": firewall.status()["active"],
                    "snmp": snmp.status,
                },
            }
            with _state_lock:
                globals()["_latest"] = state
        except Exception as e:
            with _state_lock:
                globals()["_latest"] = {"error": str(e), "ts": time.time()}
        time.sleep(max(1.0 - (time.time() - start), 0.05))


app = FastAPI(title="HomeScope")


@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "static", "index.html"))


@app.get("/api/snapshot")
def snapshot():
    with _state_lock:
        return JSONResponse(_latest)


@app.get("/api/device/{ip}")
def device(ip: str):
    detail = cap.device_detail(ip)
    with _state_lock:
        devs = (_latest.get("devices") or {}).get("devices", [])
    ident = next((d for d in devs if d.get("ip") == ip), None)
    return {"identity": ident, "detail": detail}


@app.post("/api/rescan")
def rescan():
    threading.Thread(target=tracker.scan_once, daemon=True).start()
    return {"ok": True}


# ---- domain firewall ----
@app.post("/api/block/domain")
def block_domain(payload: dict = Body(...)):
    return {"ok": blocklist.block(payload.get("domain", ""))}


@app.post("/api/unblock/domain")
def unblock_domain(payload: dict = Body(...)):
    return {"ok": blocklist.unblock(payload.get("domain", ""))}


# ---- pf firewall (gated inside the module) ----
@app.get("/api/firewall/preview")
def fw_preview(target: str):
    return firewall.preview(target)


@app.post("/api/block/ip")
def block_ip(payload: dict = Body(...)):
    return firewall.block_ip(payload.get("ip", ""))


@app.post("/api/unblock/ip")
def unblock_ip(payload: dict = Body(...)):
    return firewall.unblock_ip(payload.get("ip", ""))


@app.post("/api/firewall/flush")
def fw_flush():
    return firewall.panic_flush()


# ---- alerts ----
@app.post("/api/alerts/threshold")
def set_threshold(payload: dict = Body(...)):
    return {"ok": alerts.set_threshold(payload.get("kbps", 0) * 1024)}


# ---- export ----
@app.get("/api/export")
def export(what: str = "devices", fmt: str = "json"):
    with _state_lock:
        st = dict(_latest)
    if what == "devices":
        data = (st.get("devices") or {}).get("devices", [])
    elif what == "traffic":
        data = (st.get("traffic") or {}).get("devices", [])
    elif what == "dns":
        data = (st.get("dns") or {}).get("events", [])
    elif what == "domains":
        data = (st.get("domains") or {}).get("top", [])
    else:
        data = []
    if fmt == "csv" and data:
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(data[0].keys()), extrasaction="ignore")
        w.writeheader()
        for row in data:
            w.writerow({k: (v if not isinstance(v, (list, dict)) else json.dumps(v))
                        for k, v in row.items()})
        return PlainTextResponse(buf.getvalue(), media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={what}.csv"})
    return Response(json.dumps(data, default=str, indent=2),
                    media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename={what}.json"})


@app.websocket("/ws")
async def ws(conn: WebSocket):
    await conn.accept()
    try:
        while True:
            with _state_lock:
                payload = dict(_latest)
            await conn.send_text(json.dumps(payload, default=str))
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        return
    except Exception:
        return


app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")


def main():
    print("=" * 66)
    print("  HomeScope — whole-home network monitor (extended)")
    print(f"  Dashboard:   http://{HOST}:{PORT}")
    admin_label = "admin (full)" if sysutil.IS_WINDOWS else "root (full)"
    print(f"  Privileges:  {admin_label if IS_ROOT else 'user (discovery+presence)'}")
    print(f"  Capture:     {cap.reason}")
    print(f"  DNS watch:   {dnswatch.reason}")
    print(f"  mDNS:        {'on' if tracker.mdns.ok else 'off (pip install zeroconf)'}")
    print(f"  Sinkhole:    {sinkhole.status}")
    fw_st = firewall.status()
    fw_line = ('active' if fw_st['active']
               else fw_st['enabled'] and f"enabled (need {sysutil.admin_hint()})" or 'disabled')
    print(f"  Firewall:    {fw_line}")
    print(f"  SNMP:        {snmp.status}")
    print("=" * 66)
    tracker.start(); cap.start(); dnswatch.start(); sinkhole.start(); snmp.start()
    threading.Thread(target=sampler_loop, daemon=True).start()
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
