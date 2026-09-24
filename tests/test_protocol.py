import io
import time
import urllib.error

import pytest

import receiver
import sender

KEY = bytes.fromhex("11" * 32)
BOOT = bytes(range(16))
OTHER = bytes(16)


@pytest.fixture(autouse=True)
def english(monkeypatch):
    monkeypatch.setattr(receiver, "T", receiver.TEXT["en"])


def test_packet_is_69_bytes():
    assert receiver.SIZE == 69 == len(sender.pack(1, BOOT, 0, KEY))


def test_roundtrip():
    seen = {}
    assert receiver.verify(sender.pack(5, BOOT, 100, KEY), KEY, seen) == (5, BOOT, 100)
    assert seen[BOOT][0] == 5


def test_replay_and_reorder_rejected():
    seen, stats = {}, {}
    a, b = sender.pack(7, BOOT, 1, KEY), sender.pack(8, BOOT, 2, KEY)
    assert receiver.verify(b, KEY, seen)
    assert receiver.verify(b, KEY, seen, stats=stats) is None
    assert receiver.verify(a, KEY, seen, stats=stats) is None
    assert seen[BOOT][0] == 8
    assert stats == {"replay": 2}


def test_new_boot_starts_its_own_sequence():
    seen = {}
    assert receiver.verify(sender.pack(1000, BOOT, 5, KEY), KEY, seen)
    assert receiver.verify(sender.pack(1, OTHER, 5, KEY), KEY, seen)
    assert seen[BOOT][0] == 1000 and seen[OTHER][0] == 1


def packet(seq, ts_ms, boot=BOOT):
    # like sender.pack but with the timestamp chosen by hand
    body = receiver.BODY.pack(1, seq, ts_ms, boot, 0)
    return body + receiver.hmac.new(KEY, body, receiver.hashlib.sha256).digest()


def test_restarted_clock_gets_through_on_the_other_field():
    seen = {}
    now = int(time.time() * 1000)
    assert receiver.verify(packet(9_000_000, now), KEY, seen)
    # monotonic clock restarted (time namespace), wall clock still moving: seq is lower, ts is newer
    assert receiver.verify(packet(5, now + 1000), KEY, seen)
    # wall clock stepped back by 30 s, seq still climbing
    stepped = packet(9_000_001, now - 30_000)
    assert receiver.verify(stepped, KEY, seen)
    # the same packet again beats neither field, and neither does an older one
    assert receiver.verify(stepped, KEY, seen) is None
    assert receiver.verify(packet(4, now - 40_000), KEY, seen) is None
    assert seen[BOOT] == (9_000_001, now + 1000)


def test_wrong_key_leaves_no_trace():
    seen, stats = {}, {}
    pkt = sender.pack(1, BOOT, 0, bytes.fromhex("22" * 32))
    assert receiver.verify(pkt, KEY, seen, stats=stats) is None
    assert seen == {}
    assert stats == {"mac": 1}


def test_every_flipped_bit_is_rejected():
    pkt = sender.pack(1, BOOT, 0, KEY)
    for i in range(len(pkt)):
        for bit in range(8):
            bad = pkt[:i] + bytes([pkt[i] ^ (1 << bit)]) + pkt[i + 1:]
            assert receiver.verify(bad, KEY, {}) is None, (i, bit)


def test_wrong_size():
    pkt = sender.pack(1, BOOT, 0, KEY)
    stats = {}
    for bad in (pkt[:-1], pkt + b"\0", b""):
        assert receiver.verify(bad, KEY, {}, stats=stats) is None
    assert stats == {"size": 3}


def test_stale_packet():
    pkt = sender.pack(1, BOOT, 0, KEY)
    now = time.time()
    seen = {}
    assert receiver.verify(pkt, KEY, seen, now=now + receiver.MAX_SKEW + 1) is None
    assert receiver.verify(pkt, KEY, seen, now=now - receiver.MAX_SKEW - 1) is None
    assert seen == {}
    assert receiver.verify(pkt, KEY, seen, now=now + 10)


def test_unknown_version():
    body = receiver.BODY.pack(2, 1, int(time.time() * 1000), BOOT, 0)
    pkt = body + receiver.hmac.new(KEY, body, receiver.hashlib.sha256).digest()
    seen, stats = {}, {}
    assert receiver.verify(pkt, KEY, seen, stats=stats) is None
    assert seen == {}
    assert stats == {"version": 1}


def test_fmt():
    assert receiver.fmt(4) == "4 s"
    assert receiver.fmt(760) == "12 min 40 s"
    assert receiver.fmt(3600 * 3 + 61) == "3 h 1 min"


def test_fmt_ru(monkeypatch):
    monkeypatch.setattr(receiver, "T", receiver.TEXT["ru"])
    assert receiver.fmt(760) == "12 мин 40 с"


# the alarm logic, driven by hand with a fake clock

class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def monitor(uplink=lambda: True):
    clock, sent = Clock(), []
    mon = receiver.Monitor(5, lambda text, everyone=True: sent.append((text, everyone)), uplink, clock)
    return mon, clock, sent


def stream(mon, clock, n=5, boot=BOOT):
    # a few seconds of normal traffic, so "since start" and "since last packet" are not the same number
    for _ in range(n):
        mon.packet(boot, 10, "h")
        clock.t += 1


def test_first_packet_goes_to_the_owner_only():
    mon, _, sent = monitor()
    mon.packet(BOOT, 90, "203.0.113.7")
    assert sent == [("Receiver started, home is on the air (uptime 1 min 30 s).", False)]


def test_silence_alarms_once_and_recovery_says_no_reboot():
    mon, clock, sent = monitor()
    stream(mon, clock)
    clock.t += 4.5
    mon.tick()
    mon.tick()
    assert [t for t, _ in sent[1:]] == ["Home server is not responding (no packets for 5 s). Probably a power cut."]
    clock.t += 100
    mon.packet(BOOT, 115, "h")
    assert sent[-1] == (
        "Home server is back online (down for 1 min 45 s, no reboot, so it was probably the network).",
        True,
    )
    assert mon.down_since is None


def test_recovery_after_reboot():
    mon, clock, sent = monitor()
    stream(mon, clock)
    clock.t += 5
    mon.tick()
    clock.t += 600
    mon.packet(OTHER, 3, "h")
    assert sent[-1] == ("Home server is back online (down for 10 min 6 s, it rebooted).", True)


# regression: on day two the VPS lost its own network for 30 s and posted a false "power cut"
def test_uplink_down_holds_alarm():
    state = {"up": False}
    mon, clock, sent = monitor(lambda: state["up"])
    stream(mon, clock)
    clock.t += 5
    mon.tick()
    clock.t += 30
    mon.tick()
    assert len(sent) == 1  # nothing but the startup note
    state["up"] = True
    clock.t += 6
    mon.tick()
    assert sent[-1] == ("Home server is not responding (no packets for 42 s). Probably a power cut.", True)


def test_uplink_probe_is_throttled():
    probes = []
    mon, clock, sent = monitor(lambda: probes.append(clock.t) or False)
    stream(mon, clock)
    for _ in range(12):
        clock.t += 1
        mon.tick()
    assert probes == [1010.0, 1015.0]
    assert sent[1:] == []


def test_reboot_during_uplink_outage():
    state = {"up": False}
    mon, clock, sent = monitor(lambda: state["up"])
    stream(mon, clock)
    clock.t += 29
    mon.tick()
    mon.packet(OTHER, 4, "h")
    assert sent[-1] == ("Home server rebooted (no heartbeats for 30 s, no alarm was sent).", True)
    assert mon.uplink_down is False


def test_stray_packet_from_another_boot_is_not_a_reboot():
    mon, clock, sent = monitor()
    stream(mon, clock)
    clock.t += 0.4
    mon.packet(OTHER, 1, "h")  # a second sender started by hand somewhere
    clock.t += 0.6
    mon.packet(BOOT, 16, "h")
    assert sent[1:] == []


def test_silent_start():
    mon, clock, sent = monitor()
    clock.t += 61
    mon.tick()
    mon.tick()
    assert sent == [("Receiver started, but not a single packet from home in the first minute.", False)]
    # the receiver was restarted in the middle of an outage, so everyone hears when it ends
    mon.packet(BOOT, 40, "h")
    assert sent[-1] == ("Home server is on the air again (uptime 40 s).", True)


def test_long_outage_sounds_the_siren_and_repeats_until_power_returns():
    calls = []
    clock, sent = Clock(), []
    mon = receiver.Monitor(5, lambda text, everyone=True: sent.append(text), lambda: True, clock,
                           siren=lambda text, tts, clear=False: calls.append((clock.t, tts, clear)), siren_after=1200)
    stream(mon, clock)
    clock.t += 5
    mon.tick()  # the ordinary alarm
    clock.t += 1100
    mon.tick()
    assert calls == []
    clock.t += 100
    mon.tick()
    mon.tick()
    assert calls == [(clock.t, "No power at home for 20 minutes. Check the fuse box.", False)]
    clock.t += 600
    mon.tick()
    assert len(calls) == 2 and calls[-1][1] == "No power at home for 30 minutes. Check the fuse box."
    mon.packet(OTHER, 30, "h")
    assert calls[-1] == (clock.t, None, True)
    assert mon.next_siren is None


def test_short_outage_never_sounds_the_siren():
    calls = []
    clock, sent = Clock(), []
    mon = receiver.Monitor(5, lambda text, everyone=True: sent.append(text), lambda: True, clock,
                           siren=lambda *a, **k: calls.append(a), siren_after=1200)
    stream(mon, clock)
    clock.t += 300
    mon.tick()
    mon.packet(OTHER, 30, "h")
    assert calls == []


def test_telegram_gives_up_on_4xx_without_retrying(monkeypatch):
    calls = []

    def urlopen(url, data, timeout):
        calls.append(url)
        raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)

    monkeypatch.setattr(receiver.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(receiver, "TOKEN", "123:abc")
    monkeypatch.setattr(receiver.time, "sleep", lambda s: pytest.fail("should not sleep"))
    receiver.send_tg("42", "hi")
    assert len(calls) == 1


@pytest.mark.parametrize("header, expected", [("7", 7), ("3600", 60), ("Wed, 21 Oct 2026 07:28:00 GMT", 5)])
def test_telegram_honours_retry_after(monkeypatch, header, expected):
    calls, slept = [], []

    def urlopen(url, data, timeout):
        calls.append(url)
        if len(calls) == 1:
            raise urllib.error.HTTPError(url, 429, "Too Many Requests", {"Retry-After": header}, None)
        return io.BytesIO(b"{}")

    monkeypatch.setattr(receiver.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(receiver, "TOKEN", "123:abc")
    monkeypatch.setattr(receiver.time, "sleep", slept.append)
    receiver.send_tg("42", "hi")
    assert slept == [expected]
    assert len(calls) == 2
