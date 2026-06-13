"""Cross-platform system helpers (privileges, ping, packet-capture tool).

Keeps the OS-specific quirks in one place so the rest of HomeScope can stay
platform-agnostic. Supports macOS, Linux and Windows.
"""

import os
import shutil
import subprocess
import sys

IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


def is_admin():
    """True when running with elevated privileges.

    POSIX: effective uid 0 (root). Windows: member of the Administrators group
    with an elevated token (UAC). Falls back to False on any error.
    """
    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    # Windows: no geteuid; ask the shell whether the token is elevated.
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def admin_hint():
    """Human-readable instruction for gaining privileges on this OS."""
    if IS_WINDOWS:
        return "run from an Administrator command prompt"
    return "run with sudo"


def ping_args(ip):
    """Argv for a single, fast, quiet ping of one host on this OS."""
    if IS_WINDOWS:
        # -n count, -w timeout(ms)
        return ["ping", "-n", "1", "-w", "1000", str(ip)]
    if IS_MACOS:
        # -c count, -t ttl, -W timeout(ms)
        return ["ping", "-c", "1", "-t", "1", "-W", "300", str(ip)]
    # Linux / other: -c count, -W timeout(s)
    return ["ping", "-c", "1", "-W", "1", str(ip)]


def arp_table_cmd():
    """Argv to dump the OS ARP/neighbour cache."""
    if IS_WINDOWS:
        return ["arp", "-a"]
    # macOS/BSD use `arp -an`; on Linux that also works, with `ip neigh` as a
    # fallback handled by the caller.
    return ["arp", "-an"]


def no_window_kwargs():
    """subprocess kwargs that suppress the console-window flash on Windows.

    Empty on POSIX. On Windows the ping sweep spawns hundreds of short-lived
    `ping.exe` processes; without this each one would briefly pop a console.
    """
    if IS_WINDOWS and hasattr(subprocess, "CREATE_NO_WINDOW"):
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {}


def capture_tool():
    """Path/name of an available packet-capture CLI, or None.

    tcpdump on macOS/Linux; on Windows fall back to WinDump (the libpcap port)
    which speaks the same command-line and output format.
    """
    for tool in ("tcpdump", "windump", "WinDump"):
        if shutil.which(tool):
            return tool
    return None
