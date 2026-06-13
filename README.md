# HomeScope — whole-home network monitor + firewall

A live web dashboard that maps **every device** on your home network, shows
**per-device traffic and the domains each device talks to**, lets you **block
domains and IPs**, and **alerts** you to new devices and unusual activity — all
running locally on your machine.

Python 3.9+ · runs on **macOS, Windows and Linux**. Every feature degrades
gracefully when a platform tool is missing, and privilege/firewall/packet-capture
specifics are handled per-OS (see the platform notes below).

---

## Quick start

**macOS / Linux**
```bash
cd homenet
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # core + mDNS naming

python app.py            # device map + presence + this-host scope
#   — or, for the full picture —
sudo python app.py       # + per-device traffic + domain intel + DNS log + firewall
```

**Windows** (PowerShell)
```powershell
cd homenet
py -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

py app.py                # device map + presence + this-host scope
#   — or, for the full picture, from an *Administrator* terminal —
py app.py                # + DNS sinkhole + Windows-Firewall IP blocking
```

Open **http://127.0.0.1:8788**.

> Where macOS/Linux say "run with `sudo`", Windows means "run from an
> **Administrator** terminal". HomeScope detects elevation automatically and the
> dashboard shows what each privilege level unlocks.

> If you saw `No supported WebSocket library detected`, the dashboard can't get
> live data. Fix: `pip install 'uvicorn[standard]'` (the quotes matter in zsh),
> then restart.

---

## What's new in this version

- **Per-device drill-down** — click any device row to open a panel with its live
  traffic graph, top destinations, the domains it contacted, its protocol mix,
  and active connections. A one-click "block this IP" is right there.
- **Domain intelligence** — HomeScope matches sniffed DNS queries to their
  answers (by transaction ID) to learn which IP belongs to which domain, then
  labels traffic accordingly. You get a **per-device domain list** and a
  **global domain-by-traffic** ranking.
- **Firewall (two layers, both reversible, both opt-in):**
  - **Domain blocking — DNS sinkhole** (Pi-hole style). Blocklist is always
    tracked and matching queries are flagged in the DNS feed. Enable the
    sinkhole to actively return NXDOMAIN for blocked domains; point your router's
    DHCP DNS at this Mac and it enforces **network-wide**.
  - **IP blocking — macOS `pf`.** Off by default. When enabled and run as root,
    the dashboard adds/removes block rules inside a dedicated `homescope` pf
    anchor; "flush" removes every rule it ever added.
- **Alerts** — new device joins, a device crossing a bandwidth threshold, and
  queries to blocked domains. Set the threshold from the dashboard.
- **Export** — devices, traffic, DNS log, or domains as CSV or JSON.

Plus everything from before: discovery, presence/uptime, SNMP per-port counters,
this-Mac scope.

---

## The one physical limit (so numbers make sense)

A Mac on switched Wi-Fi only receives its own unicast traffic plus broadcasts,
so per-device byte totals from passive capture are **complete** only when this
machine sees all traffic — i.e. it's the gateway, on a hub, or on a mirrored
(SPAN) switch port. The dashboard shows how many devices it's actually seeing on
the wire. For complete accounting use **SNMP** (router per-port counters), run
HomeScope on your **gateway**, or use a **mirror port**. HomeScope does *not* use
ARP spoofing — that's the attacker's MITM trick and it degrades your network.

Note that the **DNS sinkhole** works regardless of capture coverage, because
devices send their DNS queries directly to it once you set it as their resolver.

---

## Firewall setup

### Domain blocking (recommended — works network-wide)
1. `pip install dnslib`
2. In `config.json`: `"sinkhole": { "enabled": true, "upstream": "1.1.1.1", "port": 53 }`
3. Run `sudo python app.py` (port 53 needs root).
4. On your **router**, set the DHCP DNS server to this Mac's IP.
5. Block domains from the dashboard (Firewall panel, or the "block" link on any
   DNS query). Blocked domains return NXDOMAIN for every device.

### IP blocking (this host, or whole network if this host is the gateway)
1. In `config.json`: `"firewall": { "enabled": true }`
2. Run privileged: `sudo python app.py` (macOS/Linux) or `py app.py` from an
   **Administrator** terminal (Windows).
3. Add an IP/CIDR in the Firewall panel, or "block this IP" from a device's
   drill-down. Use **flush** to clear all HomeScope rules at once.

The backend is chosen per-OS: macOS uses **pf** (a dedicated `homescope` anchor +
table), Windows uses **Windows Firewall** (`netsh advfirewall`, rules named with
a `HomeScope` prefix). On both, **flush** removes every rule the tool added and
nothing else.

Safety: the firewall is disabled until you opt in, the dashboard binds to
localhost only, every IP/domain is validated before use and passed as argv (no
shell injection), and all changes are isolated (pf anchor / `HomeScope`-named
rules) so your existing ruleset is untouched.

---

## Configuration (`config.json`)

Copy `config.example.json` to `config.json`. Sections:
- `fingerprint` — light TCP service scan for device typing (set false to stay fully passive)
- `sinkhole` — DNS domain-blocking server (see above)
- `firewall` — pf IP blocking (see above)
- `alerts.threshold_bps` — per-device bandwidth alert (bytes/sec; 0 = off)
- `snmp` — router/switch per-port polling (`brew install net-snmp`)

Env: `HOMESCOPE_HOST` (default `127.0.0.1`), `HOMESCOPE_PORT` (default `8788`).

---

## API (all localhost)

```
GET  /api/snapshot              current full state
GET  /api/device/{ip}           per-device drill-down detail
POST /api/rescan                trigger a discovery sweep
POST /api/block/domain          {"domain": "..."}
POST /api/unblock/domain        {"domain": "..."}
GET  /api/firewall/preview?target=IP    show the pf rule that would be added
POST /api/block/ip              {"ip": "IP or CIDR"}   (firewall must be enabled)
POST /api/unblock/ip            {"ip": "..."}
POST /api/firewall/flush        remove all HomeScope pf rules
POST /api/alerts/threshold      {"kbps": 500}
GET  /api/export?what=devices|traffic|dns|domains&fmt=csv|json
```

---

## Files

```
homenet/
├── app.py              # FastAPI + WebSocket; orchestrates everything + API
├── discovery.py        # device discovery + presence/uptime + mDNS + persistence
├── capture.py          # per-device traffic + destinations + connections + timeline
├── resolver.py         # domain intel + DNS watch + blocklist + sinkhole server
├── firewall.py         # IP blocking, opt-in (macOS pf anchor / Windows netsh)
├── alerts.py           # new-device / bandwidth / blocked-domain alerts
├── snmp.py             # optional per-port SNMP poller
├── oui.py              # MAC -> vendor lookup
├── sysutil.py          # cross-platform helpers (privileges, ping, arp, capture)
├── static/index.html   # dashboard UI (table, drawer, domains, firewall, alerts)
├── config.example.json
├── requirements.txt
└── README.md
```

Runtime state (outside the project, in your home dir): `~/.netscope/` holds
`devices.json`, `blocked_domains.json`, `blocked_ips.json`, `known_macs.json`.

---

## Optional dependencies
- `zeroconf` (in requirements) — mDNS/Bonjour device names + types
- `dnslib` — only if you enable the DNS sinkhole: `pip install dnslib`
- `net-snmp` — only if you enable SNMP: macOS `brew install net-snmp`, Linux
  `apt install snmp`, Windows: install the Net-SNMP binaries and put them on PATH
- **Packet capture** (per-device traffic + passive DNS log) needs a libpcap CLI:
  macOS/Linux ship `tcpdump`; on Windows install **[Npcap](https://npcap.com)**
  plus **WinDump** and ensure `WinDump.exe` is on PATH. Without it, discovery,
  presence, the DNS sinkhole, SNMP and firewalling all still work — only the
  passive sniffer features are skipped.

## Platform notes
- **Privileges** — features that need elevation light up automatically when you
  run elevated: `sudo` on macOS/Linux, an **Administrator** terminal on Windows.
- **Firewall backend** — pf on macOS, `netsh advfirewall` on Windows. Plain Linux
  has no host-firewall backend here; block on your router or use the sinkhole.
- **Discovery** — ARP parsing and the ping sweep adapt to each OS automatically
  (`arp -a` + dash-MACs on Windows, `arp -an` on macOS/Linux).

## Use responsibly
Monitor and filter only networks you own or administer.
