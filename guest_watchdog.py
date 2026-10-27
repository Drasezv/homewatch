#!/usr/bin/env python3
# Proxmox side helper: starts autostart guests that died on their own, once a minute from a systemd timer.
#
# The first version shelled out to `pct config` / `pct status` / `qm status` for every guest. Each of
# those is a Perl program that loads half of Proxmox on start, so a pass over 14 guests burned ~40 s of
# CPU every minute, half a core for nothing. This one reads the guest configs straight from /etc/pve and
# tells a running guest by its cgroup directory, so a normal pass is a few file reads. The Proxmox tools
# are only called for a guest that really is down.
import json
import os
import socket
import subprocess
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

PVE = Path(os.environ.get("GW_PVE_DIR", "/etc/pve"))
CGROUP = Path(os.environ.get("GW_CGROUP_DIR", "/sys/fs/cgroup"))
RUN = Path(os.environ.get("GW_RUN_DIR", "/var/run/qemu-server"))
DRY = os.environ.get("GW_DRY_RUN") == "1"

STARTS = {"vm": ("qmstart",), "ct": ("vzstart",)}
STOPS = {"vm": ("qmstop", "qmshutdown", "qmdestroy"), "ct": ("vzstop", "vzshutdown", "vzdestroy")}

TEXT = {
    "en": "Proxmox: {name} ({kind} {vmid}) died on its own and was started again. Check that it works.",
    "ru": "Proxmox: {name} ({kind} {vmid}) упал сам и был запущен заново сторожем. Проверь, всё ли работает.",
}


@dataclass
class Guest:
    kind: str  # "vm" or "ct"
    vmid: str
    name: str
    onboot: bool
    locked: bool


def read_guest(kind: str, conf: Path) -> Guest:
    """Only the main section counts: snapshots below the first [name] line carry their own old values."""
    fields = {}
    for line in conf.read_text(errors="replace").splitlines():
        if line.startswith("["):
            break
        key, sep, value = line.partition(":")
        if sep and not line.startswith("#"):
            fields[key.strip()] = value.strip()
    name = fields.get("name" if kind == "vm" else "hostname", conf.stem)
    return Guest(kind, conf.stem, name, fields.get("onboot") == "1", "lock" in fields)


def guests() -> list[Guest]:
    found = []
    for kind, folder in (("vm", "qemu-server"), ("ct", "lxc")):
        for conf in sorted((PVE / folder).glob("*.conf"), key=lambda p: int(p.stem) if p.stem.isdigit() else 0):
            found.append(read_guest(kind, conf))
    return found


def running(g: Guest) -> bool:
    # a running guest owns a cgroup: lxc/<id> for containers, qemu.slice/<id>.scope for VMs
    if g.kind == "ct":
        return (CGROUP / "lxc" / g.vmid).is_dir()
    if (CGROUP / "qemu.slice" / f"{g.vmid}.scope").is_dir():
        return True
    try:
        os.kill(int((RUN / f"{g.vmid}.pid").read_text().strip()), 0)
    except PermissionError:
        return True  # alive, just not ours
    except (OSError, ValueError):
        return False
    return True


def run(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout


def last_task(g: Guest, types: tuple[str, ...]) -> int:
    """Newest start time of the given task types for this guest, 0 if none."""
    out = run("pvesh", "get", f"/nodes/{socket.gethostname()}/tasks", "--vmid", g.vmid,
              "--limit", "50", "--output-format", "json")
    try:
        tasks = json.loads(out or "[]")
    except ValueError:
        return 0
    return max((t.get("starttime", 0) for t in tasks if t.get("type") in types), default=0)


def stopped_on_purpose(g: Guest) -> bool:
    stopped = last_task(g, STOPS[g.kind])
    return stopped > 0 and stopped >= last_task(g, STARTS[g.kind])


def tell(text: str) -> None:
    """POST to a Telegram-compatible sendMessage endpoint: the Bot API itself or a relay in front of it."""
    url, chat = os.environ.get("GW_NOTIFY_URL", ""), os.environ.get("GW_NOTIFY_CHAT", "")
    if not url or not chat:
        return
    req = urllib.request.Request(url, data=urllib.parse.urlencode({"chat_id": chat, "text": text}).encode(),
                                 headers={"User-Agent": "guest-watchdog/2.0"})
    if os.environ.get("GW_NOTIFY_TOKEN"):
        req.add_header("Authorization", "Bearer " + os.environ["GW_NOTIFY_TOKEN"])
    try:
        urllib.request.urlopen(req, timeout=20).close()
    except OSError as e:
        print(f"notify failed: {e}", file=sys.stderr)


def revive(g: Guest) -> None:
    print(f"{g.kind} {g.vmid} ({g.name}) died on its own, starting it", flush=True)
    if DRY:
        return
    run("qm" if g.kind == "vm" else "pct", "start", g.vmid)
    tell(TEXT.get(os.environ.get("GW_LANG", "en"), TEXT["en"]).format(name=g.name, kind=g.kind, vmid=g.vmid))


def protect_from_oom(vmids: list[str]) -> None:
    """VMs that the kernel's OOM killer should take last (say, Home Assistant)."""
    for vmid in vmids:
        try:
            pid = int((RUN / f"{vmid}.pid").read_text().strip())
            adj = Path(f"/proc/{pid}/oom_score_adj")
            if adj.read_text().strip() != "-600" and not DRY:
                adj.write_text("-600")
        except (OSError, ValueError):
            pass


def main() -> None:
    for g in guests():
        # a lock means a backup, snapshot or migration is working on it: stopped is expected
        if g.onboot and not g.locked and not running(g) and not stopped_on_purpose(g):
            revive(g)
    protect_from_oom(os.environ.get("GW_OOM_PROTECT", "").split())


if __name__ == "__main__":
    main()
