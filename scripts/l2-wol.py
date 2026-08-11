#!/usr/bin/env python3
import fcntl
import json
import re
import socket
import struct
import sys

SIOCGIFHWADDR = 0x8927


def normalize_mac(value):
    compact = re.sub(r"[^0-9a-fA-F]", "", value or "").upper()
    if len(compact) != 12:
        raise ValueError("Invalid MAC address")
    return bytes.fromhex(compact)


def get_interface_mac(interface):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(
            sock.fileno(),
            SIOCGIFHWADDR,
            struct.pack("256s", interface.encode("utf-8")[:15]),
        )
        return info[18:24]
    finally:
        sock.close()


def format_mac(value):
    return ":".join(f"{part:02X}" for part in value)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: l2-wol.py MAC INTERFACE")

    target_mac = normalize_mac(sys.argv[1])
    interface = sys.argv[2]
    source_mac = get_interface_mac(interface)
    magic_packet = b"\xff" * 6 + target_mac * 16
    ethernet_frame = b"\xff" * 6 + source_mac + b"\x08\x42" + magic_packet

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        sock.bind((interface, 0))
        sent = sock.send(ethernet_frame)
    finally:
        sock.close()

    print(json.dumps({
        "interface": interface,
        "sourceMac": format_mac(source_mac),
        "bytes": sent,
    }))


if __name__ == "__main__":
    main()
