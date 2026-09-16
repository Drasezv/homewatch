#!/usr/bin/env python3
# VPS side of homewatch. Listens for signed UDP heartbeats from the home box
# and posts to Telegram when they stop. Never sends anything back on the
# socket, so there is nothing to amplify.
import hashlib
import hmac
import os
import queue
import re
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    KEY = bytes.fromhex(os.environ.get("HB_KEY", ""))
    PORT = int(os.environ.get("HB_PORT", "29417"))
    DOWN_AFTER = float(os.environ.get("DOWN_AFTER", "5"))
except ValueError:
    print("bad value in the env file (HB_KEY, HB_PORT or DOWN_AFTER)", file=sys.stderr)
    sys.exit(78)  # EX_CONFIG, the unit file tells systemd not to restart on it
TOKEN = os.environ.get("BOT_TOKEN", "")
# first id is the owner, service messages go only there
CHATS = [c.strip() for c in os.environ.get("CHAT_ID", "").split(",") if c.strip()]
LANG = os.environ.get("HB_LANG", "en")
MAX_SKEW = 60  # seconds, both clocks have to agree this well
# telegram is the last probe on purpose: if none of these answer, an alarm
# could not be delivered anyway, so there is no point in raising one yet
PROBES = (("1.1.1.1", 443), ("8.8.8.8", 443), ("api.telegram.org", 443))

# version(1) seq(8) unix_ms(8) boot_id(16) uptime_s(4) + hmac-sha256(32)
BODY = struct.Struct("!BQQ16sI")
SIZE = BODY.size + 32

TEXT = {
    "en": {
        "down": "Home server is not responding (no packets for {t}). Probably a power cut.",
        "up_reboot": "Home server is back online (down for {t}, it rebooted).",
        "up_same": "Home server is back online (down for {t}, no reboot, so it was probably the network).",
        "reboot": "Home server rebooted (no heartbeats for {t}, no alarm was sent).",
        "first": "Receiver started, home is on the air (uptime {u}).",
        "late": "Home server is on the air again (uptime {u}).",
        "silent": "Receiver started, but not a single packet from home in the first minute.",
        "h": "h", "m": "min", "s": "s",
    },
    "ru": {
        "down": "Сервер дома не отвечает (нет пакетов {t}). Предположительно нет электричества.",
        "up_reboot": "Сервер дома снова в сети (был недоступен {t}, перезагружался).",
        "up_same": "Сервер дома снова в сети (был недоступен {t}, без перезагрузки: скорее всего, пропадал интернет).",
        "reboot": "Сервер дома перезагружался (пакетов не было {t}, тревога не отправлялась).",
        "first": "Приёмник запущен, дом на связи (аптайм {u}).",
        "late": "Дом снова на связи (аптайм {u}).",
        "silent": "Приёмник запущен, но от дома ни одного пакета за минуту.",
        "h": "ч", "m": "мин", "s": "с",
    },
}
T = TEXT.get(LANG) or TEXT["en"]


def log(msg):
    print(msg, flush=True)


def send_tg(chat, text):
    if not TOKEN:
        log("no BOT_TOKEN, would have sent: " + text)
        return
    data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    deadline = time.monotonic() + 600
    delay = 1
    while True:
        try:
            urllib.request.urlopen(url, data, timeout=10).read()
            return
        except urllib.error.HTTPError as e:
            if e.code == 429:
                try:
                    delay = min(max(int(e.headers.get("Retry-After", 5)), 1), 60)
                except (TypeError, ValueError, AttributeError):
                    delay = 5
            elif e.code < 500:
                # bad token, wrong chat id or the person blocked the bot: retrying will not help
                log(f"telegram rejected the message for chat {chat}: HTTP {e.code}")
                return
            else:
                log(f"telegram HTTP {e.code}, retrying")
        except Exception as e:
            # never log str(e) here, urllib puts the request URL (token included) into some of them.
            # .reason is the underlying error: gaierror, SSLCertVerificationError, ConnectionRefusedError
            log(f"telegram unreachable ({type(getattr(e, 'reason', e)).__name__}), retrying")
        if time.monotonic() + delay > deadline:
            log(f"giving up on a message for chat {chat} after 10 min")
            return
        time.sleep(delay)
        delay = min(delay * 2, 60)


# bounded so that a message storm (flapping link, telegram refusing us) cannot eat the memory limit
outbox = queue.Queue(maxsize=100)


def tg_worker():
    # one sender thread, so messages arrive in the order things happened
    while True:
        try:
            send_tg(*outbox.get())
        except Exception as e:
            log(f"telegram worker error: {type(e).__name__}")


def notify(text, everyone=True):
    log(text)
    for chat in (CHATS if everyone else CHATS[:1]):
        try:
            outbox.put_nowait((chat, text))
        except queue.Full:
            log(f"outbox full, dropped a message for chat {chat}")


def uplink_ok():
    for host in PROBES:
        try:
            socket.create_connection(host, timeout=1.5).close()
            return True
        except OSError:
            pass
    return False


def fmt(sec):
    sec = int(sec)
    h, m, s = sec // 3600, sec % 3600 // 60, sec % 60
    if h:
        return f"{h} {T['h']} {m} {T['m']}"
    if m:
        return f"{m} {T['m']} {s} {T['s']}"
    return f"{s} {T['s']}"


def verify(pkt: bytes, key: bytes, last_seq: dict, now: float | None = None, stats: dict | None = None):
    """Check one packet. Returns (seq, boot_id, uptime) or None.

    last_seq maps boot_id -> (highest seq, highest timestamp) accepted so far
    and gets updated on success. A packet has to beat one of the two: a held
    back or replayed packet beats neither, while a sender whose monotonic
    clock restarted (container with its own time namespace) still gets
    through on the timestamp, and one whose wall clock stepped back gets
    through on seq. stats, if given, counts rejections by reason.
    """
    def reject(why):
        if stats is not None:
            stats[why] = stats.get(why, 0) + 1

    if len(pkt) != SIZE:
        return reject("size")
    body, sig = pkt[:BODY.size], pkt[BODY.size:]
    if not hmac.compare_digest(sig, hmac.new(key, body, hashlib.sha256).digest()):
        return reject("mac")
    ver, seq, ts_ms, boot, up = BODY.unpack(body)
    if ver != 1:
        return reject("version")
    if abs((time.time() if now is None else now) - ts_ms / 1000) > MAX_SKEW:
        return reject("stale")
    top_seq, top_ts = last_seq.get(boot, (0, 0))
    if seq <= top_seq and ts_ms <= top_ts:
        return reject("replay")
    last_seq[boot] = (max(seq, top_seq), max(ts_ms, top_ts))
    return seq, boot, up


class Monitor:
    """The alarm logic, kept away from sockets so the tests can drive it with a fake clock."""

    def __init__(self, down_after, notify, uplink_ok, clock=time.monotonic):
        self.down_after = down_after
        self.notify = notify
        self.uplink_ok = uplink_ok
        self.clock = clock
        self.started = clock()
        self.last_seen = None
        self.boot = None
        self.down_since = None
        self.uplink_down = False
        self.next_probe = 0
        self.warned = False

    def packet(self, boot, up, addr):
        now = self.clock()
        said = None
        if self.last_seen is None:
            log(f"first heartbeat from {addr}, boot {boot.hex()[:8]}, uptime {up}s")
            # after a silent first minute an outage was probably in progress, so everyone hears that it ended
            said = "late" if self.warned else "first"
            self.notify(T[said].format(u=fmt(up)), everyone=self.warned)
        elif self.down_since is not None:
            said = "up_reboot" if boot != self.boot else "up_same"
            self.notify(T[said].format(t=fmt(now - self.down_since)))
            log(f"boot {boot.hex()[:8]}, uptime {up}s")
            self.down_since = None
        elif boot != self.boot and now - self.last_seen >= min(self.down_after, 10):
            # rebooted without an alarm: the gap was short, or our own uplink was down at the time.
            # A stray packet from another boot inside a live stream has no gap in front of it and stays quiet.
            said = "reboot"
            self.notify(T[said].format(t=fmt(now - self.last_seen)))
        if self.uplink_down:
            self.uplink_down = False
            if said is None:
                log("home is back, the silence was our own uplink")
        self.boot, self.last_seen = boot, now

    def tick(self):
        now = self.clock()
        if self.last_seen is None:
            if not self.warned and now - self.started > 60:
                self.warned = True
                self.notify(T["silent"], everyone=False)
            return
        if self.down_since is not None or now - self.last_seen <= self.down_after:
            return
        if self.uplink_down and now < self.next_probe:
            return
        if self.uplink_ok():
            self.down_since = self.last_seen
            self.uplink_down = False
            self.notify(T["down"].format(t=fmt(now - self.last_seen)))
        else:
            # silence can be our own uplink dying, that must not become an alarm
            if not self.uplink_down:
                log("home is silent but so is our uplink, not alarming")
            self.uplink_down = True
            self.next_probe = self.clock() + 5


def die(msg):
    print(msg, file=sys.stderr, flush=True)
    sys.exit(78)  # EX_CONFIG, the unit file tells systemd not to restart on it


def main():
    if len(KEY) < 16:
        die("HB_KEY missing or too short, generate one with: openssl rand -hex 32")
    if TOKEN and not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{30,}", TOKEN):
        die("BOT_TOKEN does not look like a bot token")
    if not 1024 <= PORT <= 65535:
        die("HB_PORT must be 1024-65535, the service has no capabilities")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    sock.settimeout(0.5)
    threading.Thread(target=tg_worker, daemon=True).start()
    log(f"listening on udp/{PORT}, alarm after {DOWN_AFTER:g}s of silence, {len(CHATS)} chat(s)")

    mon = Monitor(DOWN_AFTER, notify, uplink_ok)
    last_seq = {}
    rejects = {}
    report_at = time.monotonic() + 60
    while True:
        try:
            pkt, addr = sock.recvfrom(256)
        except TimeoutError:
            pkt = None
        hb = verify(pkt, KEY, last_seq, stats=rejects) if pkt else None
        if hb:
            mon.packet(hb[1], hb[2], addr[0])
        else:
            mon.tick()
        now = time.monotonic()
        if now > report_at:
            report_at = now + 60
            if rejects:
                log("rejected in the last minute: " + ", ".join(f"{k}={v}" for k, v in sorted(rejects.items())))
                rejects.clear()


if __name__ == "__main__":
    main()
