# homewatch

[![tests](https://github.com/Drasezv/homewatch/actions/workflows/ci.yml/badge.svg)](https://github.com/Drasezv/homewatch/actions/workflows/ci.yml)

Tells you in Telegram when the power goes out at home. The home box only talks out, so it needs no port forward and can sit on whatever address the ISP hands it.

## Why I wrote it

I wanted a phone buzz within seconds of the electricity dying at home while I'm away, and I didn't want to open anything on the home router for it. Push-style monitors (healthchecks.io, the push monitors in Uptime Kuma) go in the right direction, but they ping over HTTPS, and they count gaps in minutes (healthchecks.io) or 20 s (Uptime Kuma before 2.1; newer versions go down to 1 s, at an HTTPS request a second). None of them can tell a reboot from a dropped link either. So: a 69-byte UDP packet once a second to a cheap VPS, and the VPS never answers. When the packets stop, it posts to Telegram. When they come back, it says whether the machine rebooted.

Running on my own home server since 2026-09-15.

## How it works

```
 home server                                  VPS
 +-----------------------+                    +--------------------------+
 | sender.py             |  UDP, 69 bytes     | receiver.py              |
 | every 1 s:            | -----------------> | checks HMAC + freshness  |
 |  seq, time, boot_id,  |  (nothing comes    | silence > 5 s  -> alarm  |
 |  uptime, HMAC-SHA256  |   back, ever)      | packets again  -> clear  |
 +-----------------------+                    +------------+-------------+
                                                           | Telegram Bot API
                                                           v
                                                       your phone
```

The alarm fires after `DOWN_AFTER` seconds without a valid packet (5 by default). Each packet carries the kernel's `boot_id`, so when the heartbeat returns the receiver knows what happened: new `boot_id`, it was the power; same `boot_id`, it was the network. If the `boot_id` changes without an alarm having gone out (the gap was shorter than `DOWN_AFTER`, or the VPS itself was cut off at the time), you still get a message saying the box rebooted.

Before alarming, the receiver checks that it can reach the internet itself (TCP to 1.1.1.1, 8.8.8.8 and api.telegram.org). If its own uplink is what died it stays quiet, and alarms once the uplink is back if the home is still silent. The check exists because of two false alarms on the second day: the VPS lost its own network for 30 s, and later for 5 s.

Messages you can get:

- `Home server is not responding (no packets for 5 s). Probably a power cut.`
- `Home server is back online (down for 12 min 40 s, it rebooted).`
- `Home server is back online (down for 30 s, no reboot, so it was probably the network).`
- `Home server rebooted (no heartbeats for 40 s, no alarm was sent).`

plus two owner-only service messages: one when the receiver starts and hears the first heartbeat, one when it hears nothing at all in its first minute. Texts exist in English and Russian (`HB_LANG`).

## Packet format

| offset | size | field | meaning |
|---|---|---|---|
| 0 | 1 | version | always 1 |
| 1 | 8 | seq | microseconds of the sender's monotonic clock, so a restarted sender never goes backwards within one boot |
| 9 | 8 | time | sender's unix time in ms, rejected if off by more than 60 s |
| 17 | 16 | boot_id | `/proc/sys/kernel/random/boot_id`, changes only on reboot |
| 33 | 4 | uptime | seconds since boot (the container's, under lxcfs), shown in the log and in the owner's startup message |
| 37 | 32 | hmac | HMAC-SHA256 over the 37 bytes above, keyed with the shared secret |

Big-endian, `struct` format `!BQQ16sI`. A packet is accepted only if it's exactly 69 bytes, the MAC verifies, the version byte is 1, the timestamp is within 60 s of the receiver's clock, and either `seq` or the timestamp is newer than the last accepted packet for that `boot_id` (one of the two clocks may misbehave, a held-back packet loses on both). Anything else is dropped without a log line; instead the receiver prints one summary for every minute in which something was rejected (`rejected in the last minute: stale=60`), which is how you'd notice a clock problem. A flood of garbage costs at most one HMAC per packet.

The 60 s window is there for the receiver restarting and forgetting its sequence numbers, and it bounds how long a packet can be held back on the path. It assumes NTP on both machines; drift beyond a minute makes every heartbeat look stale: an alarm that never clears, or, if the clocks disagree from the start, only the "not a single packet" message. The summary line in the journal says `stale` either way.

## Design notes

### UDP, one direction

The heartbeat has to get through on a bad link, so there's no handshake and no connection state; if a packet is lost, the next one is a second behind it. The receiver never sends anything back on the socket, so there is nothing to amplify, and the home side needs no inbound rules. At one packet a second that's 69 bytes of payload, about 250 MB a month with IP and UDP headers.

### HMAC rather than TLS

Both ends are mine and share one 32-byte secret. That gives authenticity and integrity for 32 bytes of overhead with the standard library only. Confidentiality isn't a goal: a packet says "I'm alive at time T, booted with id X, up for U seconds", and someone on the path could work out most of that from timing alone. The bot token is as sensitive as the key, whoever has it can post a fake "back online".

### Why boot_id

Uptime would be the obvious reboot detector, and under lxcfs it's the wrong one: `/proc/uptime` inside the container is the container's uptime, not the host's. `boot_id` is a random UUID the kernel makes once per boot, and inside an LXC container it is the host's value, which is the machine I'm actually watching. (systemd-nspawn gives each container its own `boot_id`; there you'd run the sender on the host.)

## Install

Everything below runs as root. Both scripts are plain Python 3.10 or newer, standard library only; here the receiver runs on Ubuntu 24.04 (Python 3.12) and the sender on Debian 13 (3.13).

### Receiver (VPS)

```sh
apt install -y git python3
git clone https://github.com/Drasezv/homewatch /opt/homewatch
chmod -R a+rX /opt/homewatch         # the service runs as a throwaway user
mkdir -p /etc/homewatch
cp /opt/homewatch/receiver.env.example /etc/homewatch/receiver.env
chmod 600 /etc/homewatch/receiver.env
timedatectl show -p NTPSynchronized  # must say yes
```

Fill in `/etc/homewatch/receiver.env`:

- `HB_KEY`: shared secret, `openssl rand -hex 32`, the same value goes to the sender
- `BOT_TOKEN`: from @BotFather. Open the bot and press Start, a bot can't message you before that
- `CHAT_ID`: your Telegram id (@userinfobot tells you), or several separated by commas; the first one is the owner and also gets the service messages
- `DOWN_AFTER`: seconds of silence before the alarm, default 5
- `HB_PORT`: default 29417
- `HB_LANG`: `en` or `ru`

Then:

```sh
cp /opt/homewatch/systemd/homewatch-receiver.service /etc/systemd/system/
systemctl enable --now homewatch-receiver
journalctl -fu homewatch-receiver
```

If ufw is active (`ufw status`), `ufw allow 29417/udp`. If the provider has a cloud firewall in front of the VPS, open UDP 29417 there instead. Outbound 443 is needed for Telegram and is open by default.

### Sender (home)

```sh
apt install -y git python3
git clone https://github.com/Drasezv/homewatch /opt/homewatch
chmod -R a+rX /opt/homewatch
mkdir -p /etc/homewatch
cp /opt/homewatch/sender.env.example /etc/homewatch/sender.env
chmod 600 /etc/homewatch/sender.env
```

Put the same `HB_KEY` and the VPS address (`HB_HOST`) into the env file. Use the IP, not a hostname: DNS is one of the things that may still be broken right after the box comes back up.

```sh
cp /opt/homewatch/systemd/homewatch-sender.service /etc/systemd/system/
systemctl enable --now homewatch-sender
```

The journal on the VPS now shows `first heartbeat from <your ip>, boot 1a2b3c4d, uptime 812s`, and the owner gets a message that the receiver started and the home is on the air. That message is also how you find out that the token and the chat id are right.

Mine lives in a 128 MB LXC container on the home server, set to start first after boot. An unprivileged Proxmox container needs `features: nesting=1` (`pct config <id> | grep features`), otherwise systemd can't set up the unit's mount namespace and the service fails with `226/NAMESPACE`. The container shares the host's clock, so there's nothing to sync inside it; check `timedatectl` on the host.

Both units run under `DynamicUser` with most of the systemd sandbox switched on: no capabilities, `ProtectSystem=strict`, an `@system-service` syscall allow list, Internet sockets only. `systemd-analyze security` puts both at 1.5, "OK"; what it still lists is mostly network access, which a network daemon can't give up. The services never write under `/opt`: a script passed to `python3` directly is never cached to `__pycache__`, and the scripts import nothing of their own.

### Day to day

- Key rotation: put the new key in both env files, restart the receiver first (a fresh receiver can't alarm, it has seen nothing yet), then the sender within a minute. The other order gives you a false "power cut".
- Upgrade: `cd /opt/homewatch && git pull && systemctl restart homewatch-receiver`, same on the home side with the sender. `/opt` is read-only only inside the service's namespace. After editing a unit file, `systemctl daemon-reload`.
- A sender crash restarts it in 1 s, under the 5 s threshold, so it never shows up as an outage. A config mistake the scripts check for (missing or malformed key, malformed token, port below 1024, a non-number where a number is expected) exits with code 78 and the unit stays stopped instead of looping.

## Trying it out

Stop the sender for ten seconds:

```sh
systemctl stop homewatch-sender; sleep 10; systemctl start homewatch-sender
```

The alarm comes about five seconds in, and the "back online" message that says "no reboot" right after the start. For the real thing, pull the plug; that message will say it rebooted.

To exercise the uplink logic on the VPS:

```sh
for h in 1.1.1.1 8.8.8.8 api.telegram.org; do iptables -I OUTPUT -p tcp -d $h --dport 443 -j REJECT; done
systemctl stop homewatch-sender      # on the home side
```

The journal says `home is silent but so is our uplink, not alarming` and nothing reaches Telegram. Start the sender again, then remove the rules with the same loop and `-D` instead of `-I`.

## Guest watchdog (Proxmox)

`guest_watchdog.py` is a separate helper for the Proxmox host itself. Once a minute it looks for guests marked to start at boot that are stopped although nobody stopped them, starts them again and sends a Telegram message. I wrote it after the kernel's OOM killer took the Home Assistant VM and nobody noticed for eleven hours.

A guest counts as stopped on purpose when its last stop, shutdown or destroy task is newer than its last start. A guest with a `lock` (a stop-mode backup, a snapshot, a migration) is skipped. `GW_OOM_PROTECT` moves the listed VMs to the back of the OOM killer's queue.

The first version asked `pct` and `qm` about every guest every minute. Those are Perl programs that load a good part of Proxmox on each start, and with 14 guests a pass cost about 40 s of CPU: half a core, all the time. This one reads the configs from `/etc/pve` and tells a running guest by its cgroup directory, so a normal pass is a handful of file reads. The Proxmox tools only run for a guest that is actually down.

```sh
install -m 755 guest_watchdog.py /usr/local/sbin/guest_watchdog.py
install -m 600 guest-watchdog.env.example /etc/guest-watchdog.env   # then edit it
cp systemd/guest-watchdog.service systemd/guest-watchdog.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now guest-watchdog.timer
GW_DRY_RUN=1 python3 /usr/local/sbin/guest_watchdog.py              # prints what it would start
```

## Tests

```sh
apt install -y python3-pytest     # or: pip install pytest, where pip is allowed to
python3 -m pytest -q
```

They cover the packet round trip, wrong size, wrong key, every single flipped bit of a packet (552 of them), replay and reordering, stale timestamps, an unknown version byte, a new `boot_id` starting its own sequence, a clock restart on either side still getting through, the duration formatter in both languages, and the alarm logic itself with a fake clock: silence, recovery with and without a reboot, the alarm held back while the VPS's own uplink is down (the two false alarms from day two), a reboot hidden behind that outage, a stray packet from another boot, the silent-start warning, and how the Telegram sender treats a 403, a 429 and a garbage `Retry-After`. For the guest watchdog: running guests cost no tool calls, a dead container or VM is started, one stopped on purpose or locked by a backup is left alone, snapshot sections are ignored, and the dry run only prints.

## Limitations

- It only knows whether packets arrive. A frozen machine whose container still sends heartbeats looks alive.
- A dead home router with the server still up gets you the power-cut alarm first, then the back-online message with `no reboot` that corrects it.
- All state lives in memory. If the receiver restarts during an outage, nobody gets an alarm for it; the owner gets the "not a single packet" note after a minute, and everyone gets "home is on the air again (uptime 40 s)" when it returns, which tells the story anyway.
- If the VPS itself is down, nobody tells you anything.
- Someone on the path can hold packets back and release them up to 60 s later, which delays the alarm by that much; dropping them gives a false alarm. Replaying a packet the receiver has already seen does nothing, and nobody can forge one without the key.
- Anyone who knows the address can flood the port. That doesn't crash anything (each packet costs a length check and at most one HMAC), but a flood that overruns the socket buffer makes the real packets late and produces false alarms, with a message for each of them (the outbox holds 100, after that they are dropped with a log line). If the home's ISP prefix is stable, restrict the port to it in the firewall.
- An unstable link produces an alarm and a recovery message for every gap longer than `DOWN_AFTER`. Raise it if that gets noisy; reboots shorter than it are still reported through the `boot_id` change.
- The heartbeat socket is IPv4 only.

## License

MIT
