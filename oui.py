"""MAC address -> vendor lookup.

Ships with a compact built-in table of common home-network vendors so it works
fully offline. If you drop a standard IEEE `oui.txt` or Wireshark `manuf` file
next to this module, it will be loaded too for full coverage.
"""

import os
import re

# First 3 octets (uppercase hex, no separators) -> vendor label.
BUILTIN = {
    # Apple
    "001451": "Apple", "0017F2": "Apple", "002332": "Apple", "0050E4": "Apple",
    "3C0754": "Apple", "A4B197": "Apple", "F0DBF8": "Apple", "AC87A3": "Apple",
    "D49A20": "Apple", "F4F15A": "Apple", "B8E856": "Apple", "8C8590": "Apple",
    "F02475": "Apple", "8866A5": "Apple", "DC2B2A": "Apple", "A85C2C": "Apple",
    # Samsung
    "0015B9": "Samsung", "5001BB": "Samsung", "8425DB": "Samsung",
    "BC851F": "Samsung", "0021D1": "Samsung", "F008F1": "Samsung",
    # Google / Nest / Chromecast
    "F4F5D8": "Google", "F4F5E8": "Google", "3C5AB4": "Google",
    "DA A1 19".replace(" ", ""): "Google", "001A11": "Google", "54600D": "Google",
    # Amazon (Echo, Fire, Ring)
    "FCA667": "Amazon", "44650D": "Amazon", "68543D": "Amazon",
    "0C47C9": "Amazon", "F0272D": "Amazon", "B47C9C": "Amazon",
    # Espressif (ESP8266/ESP32 — most DIY/IoT smart devices)
    "240AC4": "Espressif/IoT", "30AEA4": "Espressif/IoT", "8CAAB5": "Espressif/IoT",
    "A4CF12": "Espressif/IoT", "B4E62D": "Espressif/IoT", "CC50E3": "Espressif/IoT",
    "DC4F22": "Espressif/IoT", "ECFABC": "Espressif/IoT", "246F28": "Espressif/IoT",
    # Raspberry Pi
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "2CCF67": "Raspberry Pi", "D83ADD": "Raspberry Pi",
    # TP-Link / networking
    "001478": "TP-Link", "50C7BF": "TP-Link", "EC086B": "TP-Link", "F4F26D": "TP-Link",
    # Netgear
    "00146C": "Netgear", "A040A0": "Netgear", "3894ED": "Netgear",
    # Ubiquiti
    "002722": "Ubiquiti", "245A4C": "Ubiquiti", "788A20": "Ubiquiti", "FCECDA": "Ubiquiti",
    "B4FBE4": "Ubiquiti", "687251": "Ubiquiti",
    # ASUS
    "001BFC": "ASUS", "2C56DC": "ASUS", "AC220B": "ASUS",
    # Intel (laptops/NICs)
    "001500": "Intel", "3CA9F4": "Intel", "A0A8CD": "Intel", "7C7A91": "Intel",
    # Sonos
    "000E58": "Sonos", "5CAAFD": "Sonos", "B8E937": "Sonos",
    # Philips Hue / Signify
    "001788": "Philips Hue", "ECB5FA": "Philips Hue",
    # Roku
    "B0A737": "Roku", "DC3A5E": "Roku", "CC6DA0": "Roku",
    # Sony / LG (TVs)
    "FCF152": "Sony", "8C79F5": "LG", "A816B2": "LG",
    # Microsoft (Xbox / Surface)
    "000D3A": "Microsoft", "7C1E52": "Microsoft", "C83F26": "Microsoft",
    # HP / printers
    "001B78": "HP", "9C8E99": "HP", "3024A9": "HP",
    # Dyson, Wyze, Tuya, Shelly (popular smart home)
    "D073D5": "LIFX", "2CAA8E": "Wyze", "A0E6F8": "TUYA/Smart",
    "B0B21C": "Shelly", "98CDAC": "Espressif/IoT",
    # Virtualization / VM platforms (common in dev/test setups)
    "001C42": "Parallels VM", "080027": "VirtualBox VM", "0A0027": "VirtualBox VM",
    "00155D": "Hyper-V VM", "525400": "QEMU/KVM VM", "00163E": "Xen VM",
    "000569": "VMware", "000C29": "VMware", "001C14": "VMware", "005056": "VMware",
    "0050F2": "Microsoft", "024286": "Docker",
}

_full = {}


def _load_full_files():
    here = os.path.dirname(os.path.abspath(__file__))
    for fname in ("oui.txt", "manuf", "oui.csv"):
        path = os.path.join(here, fname)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Wireshark manuf:  AA:BB:CC<TAB>Short  Long
                    m = re.match(r"^([0-9A-Fa-f]{2}[:\-]){2}[0-9A-Fa-f]{2}", line)
                    if m:
                        prefix = re.sub(r"[:\-]", "", m.group(0)).upper()
                        rest = line[len(m.group(0)):].strip().split("\t")
                        vendor = (rest[0] if rest else "").strip()
                        if vendor:
                            _full[prefix] = vendor
                        continue
                    # IEEE oui.txt:  AABBCC     (hex)\t\tVendor
                    m = re.match(r"^([0-9A-Fa-f]{6})\s+\(hex\)\s+(.+)$", line)
                    if m:
                        _full[m.group(1).upper()] = m.group(2).strip()
        except Exception:
            pass


_load_full_files()


def normalize(mac):
    if not mac:
        return None
    h = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    return h if len(h) >= 6 else None


def lookup(mac):
    h = normalize(mac)
    if not h:
        return None
    prefix = h[:6]
    return _full.get(prefix) or BUILTIN.get(prefix)


def is_locally_administered(mac):
    """True for randomized/private MACs (common on modern phones)."""
    h = normalize(mac)
    if not h:
        return False
    try:
        second_nibble = int(h[1], 16)
        return bool(second_nibble & 0x2)
    except ValueError:
        return False
