#!/usr/bin/env python3
# Home side of homewatch: one signed UDP packet every HB_INTERVAL seconds.
import hashlib
import hmac
import os
import socket
import struct
import sys
import time

try:
    KEY = bytes.fromhex(os.environ.get("HB_KEY", ""))
    PORT = int(os.environ.get("HB_PORT", "29417"))
    INTERVAL = float(os.environ.get("HB_INTERVAL", "1"))
except ValueError:
    print("bad value in the env file (HB_KEY, HB_PORT or HB_INTERVAL)", file=sys.stderr)
    sys.exit(78)  # EX_CONFIG, see RestartPreventExitStatus in the unit
HOST = os.environ.get("HB_HOST", "")

# version(1) seq(8) unix_ms(8) boot_id(16) uptime_s(4) + hmac-sha256(32)
BODY = struct.Struct("!BQQ16sI")


def boot_id() -> bytes:
    # inside an LXC container this is the host kernel's boot_id, which is
    # what we want: it only changes when the whole box reboots
    with open("/proc/sys/kernel/random/boot_id") as f:
        return bytes.fromhex(f.read().strip().replace("-", ""))


def uptime() -> int:
    # decoration for the log on the other side, never worth losing a packet over
    # (lxcfs can leave /proc/uptime returning ENOTCONN after a restart)
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except Exception:
        return 0


def pack(seq: int, boot: bytes, up: int, key: bytes) -> bytes:
    body = BODY.pack(1, seq, int(time.time() * 1000), boot, up)
    return body + hmac.new(key, body, hashlib.sha256).digest()


if __name__ == "__main__":
    try:
        socket.inet_aton(HOST)
    except OSError:
        HOST = ""
    if len(KEY) < 16 or not HOST or INTERVAL <= 0:
        print("need HB_KEY (openssl rand -hex 32), HB_HOST as an IPv4 address, HB_INTERVAL > 0", file=sys.stderr)
        sys.exit(78)  # EX_CONFIG, see RestartPreventExitStatus in the unit
    try:
        boot = boot_id()
    except OSError:
        print("cannot read /proc/sys/kernel/random/boot_id, is /proc hidden from the service?", file=sys.stderr)
        sys.exit(78)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"sending to {HOST}:{PORT} every {INTERVAL:g}s, boot {boot.hex()[:8]}", flush=True)
    while True:
        # microseconds of the monotonic clock: a restarted sender (or a second
        # copy started by hand) can never fall below what the receiver already
        # accepted for this boot, and a wall-clock step does not touch it
        seq = time.monotonic_ns() // 1000
        try:
            sock.sendto(pack(seq, boot, uptime(), KEY), (HOST, PORT))
        except OSError:
            pass
        time.sleep(INTERVAL)
