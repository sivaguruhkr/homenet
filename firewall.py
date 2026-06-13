"""Opt-in IP firewall — macOS (pf) and Windows (netsh advfirewall).

Safety model (identical on both platforms):
  * Disabled by default. Nothing here mutates the system unless config.json has
    {"firewall": {"enabled": true}} AND the process is privileged.
  * All blocking is isolated so a single flush removes every rule this tool ever
    added — macOS uses a DEDICATED pf anchor + table named "homescope"; Windows
    uses Windows Firewall rules all named with the "HomeScope" prefix. We never
    touch your other rules. "panic_flush" clears ours instantly.
  * Inputs are validated as real IPs/CIDRs with the stdlib `ipaddress` module and
    passed to pfctl/netsh as argv (never shell-interpolated), so a crafted value
    cannot inject a command.

Honest scope:
  A host firewall filters only THIS machine's traffic. To block a device for the
  whole house, block it on your router, or use the DNS sinkhole (resolver.py) for
  domain-level blocking network-wide.
"""

import ipaddress
import json
import os
import subprocess
import threading

import sysutil

STATE_DIR = os.path.expanduser("~/.netscope")
FW_FILE = os.path.join(STATE_DIR, "blocked_ips.json")
ANCHOR = "homescope"
TABLE = "homescope_block"
WIN_RULE_PREFIX = "HomeScope"

SCOPE_NOTE = ("the host firewall filters only this machine unless it is your "
              "gateway; use the DNS sinkhole or your router for network-wide blocks.")


def valid_target(value):
    """Return a normalized IP/CIDR string, or None if not valid."""
    try:
        if "/" in (value or ""):
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except Exception:
        return None


class _BaseFirewall:
    """Shared persistence, validation and bookkeeping for all backends."""

    backend = "none"

    def __init__(self, cfg):
        cfg = cfg or {}
        self.enabled = bool(cfg.get("enabled"))
        self.is_root = sysutil.is_admin()
        self.blocked = set()
        self.lock = threading.Lock()
        self.last_error = None
        self.load()

    # ---- persistence (shared) ----
    def load(self):
        try:
            with open(FW_FILE) as fh:
                for t in json.load(fh).get("ips", []):
                    n = valid_target(t)
                    if n:
                        self.blocked.add(n)
        except Exception:
            pass

    def save(self):
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with self.lock:
                data = {"ips": sorted(self.blocked)}
            with open(FW_FILE + ".tmp", "w") as fh:
                json.dump(data, fh)
            os.replace(FW_FILE + ".tmp", FW_FILE)
        except Exception:
            pass

    @property
    def active(self):
        return self.enabled and self.is_root and self.backend != "none"

    def status(self):
        return {
            "enabled": self.enabled,
            "is_root": self.is_root,
            "backend": self.backend,
            "blocked_ips": sorted(self.blocked),
            "anchor": ANCHOR,
            "active": self.active,
            "error": self.last_error,
            "hint": sysutil.admin_hint(),
            "note": SCOPE_NOTE,
        }

    # ---- mutating ops (gated; backend supplies _apply) ----
    def block_ip(self, target):
        n = valid_target(target)
        if not n:
            return {"ok": False, "error": "not a valid IP or CIDR"}
        with self.lock:
            self.blocked.add(n)
        self.save()
        ok = self._apply()
        return {"ok": ok, "target": n, "error": self.last_error if not ok else None}

    def unblock_ip(self, target):
        n = valid_target(target)
        with self.lock:
            self.blocked.discard(n)
        self.save()
        ok = self._apply()
        return {"ok": ok, "target": n}

    # backends override these
    def _apply(self):
        return False

    def preview(self, target):
        n = valid_target(target)
        if not n:
            return {"ok": False, "error": "not a valid IP or CIDR"}
        return {"ok": True, "target": n, "rules": f"# block {n} ({self.backend})"}

    def panic_flush(self):
        with self.lock:
            self.blocked.clear()
        self.save()
        return {"ok": True}


class PFFirewall(_BaseFirewall):
    """macOS packet-filter (pf) backend — isolated anchor + table."""

    backend = "pf"

    def status(self):
        st = super().status()
        info = self._pfctl(["-s", "info"], read_only=True)
        st["pf_enabled"] = "Status: Enabled" in (info or "")
        return st

    def _pfctl(self, args, read_only=False):
        if not read_only and not (self.enabled and self.is_root):
            self.last_error = "firewall disabled or not root"
            return None
        try:
            r = subprocess.run(["pfctl"] + args, capture_output=True,
                               text=True, timeout=8)
            return (r.stdout or "") + (r.stderr or "")
        except FileNotFoundError:
            self.last_error = "pfctl not found (not macOS?)"
            return None
        except Exception as e:
            self.last_error = str(e)
            return None

    def _rules_text(self):
        # Dedicated anchor: block traffic to/from the homescope table.
        return (f"table <{TABLE}> persist\n"
                f"block drop quick from <{TABLE}>\n"
                f"block drop quick to <{TABLE}>\n")

    def _apply(self):
        """Load the anchor rules and sync the table to self.blocked."""
        if not (self.enabled and self.is_root):
            self.last_error = "firewall disabled or not root"
            return False
        try:
            p = subprocess.run(["pfctl", "-a", ANCHOR, "-f", "-"],
                               input=self._rules_text(), text=True,
                               capture_output=True, timeout=8)
            if p.returncode != 0:
                self.last_error = p.stderr.strip() or "pfctl load failed"
        except Exception as e:
            self.last_error = str(e)
            return False
        with self.lock:
            targets = sorted(self.blocked)
        args = ["pfctl", "-a", ANCHOR, "-t", TABLE, "-T", "replace"] + targets
        try:
            subprocess.run(args, capture_output=True, text=True, timeout=8)
        except Exception as e:
            self.last_error = str(e)
            return False
        self._pfctl(["-e"])   # ensure pf is on
        return True

    def preview(self, target):
        n = valid_target(target)
        if not n:
            return {"ok": False, "error": "not a valid IP or CIDR"}
        return {"ok": True, "target": n,
                "rules": self._rules_text() + f"# table <{TABLE}> add {n}"}

    def panic_flush(self):
        """Remove every rule/table entry this tool added."""
        self._pfctl(["-a", ANCHOR, "-F", "all"])
        self._pfctl(["-a", ANCHOR, "-t", TABLE, "-T", "flush"])
        return super().panic_flush()


class WinFirewall(_BaseFirewall):
    """Windows backend — Windows Firewall rules via `netsh advfirewall`.

    Each blocked target gets two rules (inbound + outbound) sharing one name
    "HomeScope <target>", so a single delete-by-name removes both, and flush
    just deletes every name we created.
    """

    backend = "netsh"

    def _rule_name(self, target):
        return f"{WIN_RULE_PREFIX} {target}"

    def _netsh(self, args):
        try:
            r = subprocess.run(["netsh", "advfirewall", "firewall"] + args,
                               capture_output=True, text=True, timeout=8,
                               **sysutil.no_window_kwargs())
            return r.returncode, (r.stdout or "") + (r.stderr or "")
        except FileNotFoundError:
            self.last_error = "netsh not found (not Windows?)"
            return 1, ""
        except Exception as e:
            self.last_error = str(e)
            return 1, ""

    def _delete_rule(self, target):
        # idempotent: deleting a non-existent rule just returns non-zero
        self._netsh(["delete", "rule", f"name={self._rule_name(target)}"])

    def _add_rule(self, target):
        name = self._rule_name(target)
        ok = True
        for direction in ("in", "out"):
            rc, out = self._netsh(["add", "rule", f"name={name}",
                                   f"dir={direction}", "action=block",
                                   f"remoteip={target}"])
            if rc != 0:
                ok = False
                self.last_error = out.strip() or "netsh add rule failed"
        return ok

    def _apply(self):
        """Reconcile Windows Firewall with self.blocked (delete-then-add)."""
        if not (self.enabled and self.is_root):
            self.last_error = "firewall disabled or not administrator"
            return False
        with self.lock:
            targets = sorted(self.blocked)
        ok = True
        for t in targets:
            self._delete_rule(t)        # avoid duplicate rules on re-apply
            if not self._add_rule(t):
                ok = False
        return ok

    def preview(self, target):
        n = valid_target(target)
        if not n:
            return {"ok": False, "error": "not a valid IP or CIDR"}
        name = self._rule_name(n)
        return {"ok": True, "target": n,
                "rules": (f'netsh advfirewall firewall add rule name="{name}" '
                          f'dir=out action=block remoteip={n}\n'
                          f'netsh advfirewall firewall add rule name="{name}" '
                          f'dir=in action=block remoteip={n}')}

    def panic_flush(self):
        """Delete every HomeScope firewall rule this tool added."""
        if self.enabled and self.is_root:
            with self.lock:
                targets = sorted(self.blocked)
            for t in targets:
                self._delete_rule(t)
        return super().panic_flush()


class NullFirewall(_BaseFirewall):
    """Fallback for platforms without a supported backend (e.g. plain Linux)."""

    backend = "none"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.last_error = ("no supported host-firewall backend on this OS; "
                           "use your router or the DNS sinkhole")


def make_firewall(cfg):
    """Pick the IP-firewall backend appropriate for the current OS."""
    if sysutil.IS_MACOS:
        return PFFirewall(cfg)
    if sysutil.IS_WINDOWS:
        return WinFirewall(cfg)
    return NullFirewall(cfg)
