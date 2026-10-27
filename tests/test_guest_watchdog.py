import json
import os

import pytest

import guest_watchdog as gw


@pytest.fixture
def box(tmp_path, monkeypatch):
    """A fake Proxmox node: config folders, cgroup tree, pid files, and a recorder for the tools it would call."""
    for d in ("pve/qemu-server", "pve/lxc", "cg/lxc", "cg/qemu.slice", "run"):
        (tmp_path / d).mkdir(parents=True)
    monkeypatch.setattr(gw, "PVE", tmp_path / "pve")
    monkeypatch.setattr(gw, "CGROUP", tmp_path / "cg")
    monkeypatch.setattr(gw, "RUN", tmp_path / "run")
    monkeypatch.setattr(gw, "DRY", False)
    calls, told, tasks = [], [], {}

    def run(*cmd):
        calls.append(cmd)
        if cmd[:2] == ("pvesh", "get"):
            return json.dumps(tasks.get(cmd[cmd.index("--vmid") + 1], []))
        return ""

    monkeypatch.setattr(gw, "run", run)
    monkeypatch.setattr(gw, "tell", told.append)

    class Box:
        def ct(self, vmid, conf, up=False):
            (tmp_path / "pve/lxc" / f"{vmid}.conf").write_text(conf)
            if up:
                (tmp_path / "cg/lxc" / vmid).mkdir()

        def vm(self, vmid, conf, up=False):
            (tmp_path / "pve/qemu-server" / f"{vmid}.conf").write_text(conf)
            if up:
                (tmp_path / "cg/qemu.slice" / f"{vmid}.scope").mkdir()

        def started(self):
            return [c for c in calls if c[1:2] == ("start",)]

        def pvesh_calls(self):
            return [c for c in calls if c[0] == "pvesh"]

    b = Box()
    b.calls, b.told, b.tasks = calls, told, tasks
    return b


def test_running_guests_cost_no_proxmox_tool_calls(box):
    box.ct("101", "hostname: mqtt\nonboot: 1\n", up=True)
    box.vm("100", "name: ha\nonboot: 1\n", up=True)
    gw.main()
    assert box.calls == []


def test_dead_container_is_started_and_reported(box):
    box.ct("102", "hostname: zigbee\nonboot: 1\n")
    gw.main()
    assert box.started() == [("pct", "start", "102")]
    assert len(box.told) == 1 and "zigbee" in box.told[0]


def test_dead_vm_is_started_with_qm(box):
    box.vm("100", "name: ha\nonboot: 1\n")
    gw.main()
    assert box.started() == [("qm", "start", "100")]


def test_guest_stopped_on_purpose_is_left_alone(box):
    box.ct("103", "hostname: lab\nonboot: 1\n")
    box.tasks["103"] = [{"type": "vzstart", "starttime": 100}, {"type": "vzshutdown", "starttime": 200}]
    gw.main()
    assert box.started() == []


def test_start_after_the_last_stop_means_it_died(box):
    box.ct("103", "hostname: lab\nonboot: 1\n")
    box.tasks["103"] = [{"type": "vzstop", "starttime": 100}, {"type": "vzstart", "starttime": 200}]
    gw.main()
    assert box.started() == [("pct", "start", "103")]


def test_no_autostart_no_touch(box):
    box.ct("104", "hostname: spare\nonboot: 0\n")
    box.ct("105", "hostname: other\n")
    gw.main()
    assert box.calls == []


def test_locked_guest_is_skipped(box):
    # a stop-mode backup keeps the guest down for a while with lock: backup
    box.ct("106", "hostname: busy\nonboot: 1\nlock: backup\n")
    gw.main()
    assert box.calls == []


def test_snapshot_sections_do_not_count(box):
    box.ct("107", "hostname: snap\n\n[before-upgrade]\nhostname: snap\nonboot: 1\n")
    gw.main()
    assert box.calls == []


def test_vm_found_by_pid_file_when_cgroup_is_elsewhere(box, tmp_path):
    box.vm("100", "name: ha\nonboot: 1\n")
    (tmp_path / "run" / "100.pid").write_text(str(os.getpid()))
    gw.main()
    assert box.started() == []


def test_dry_run_only_prints(box, monkeypatch, capsys):
    monkeypatch.setattr(gw, "DRY", True)
    box.ct("102", "hostname: zigbee\nonboot: 1\n")
    gw.main()
    assert box.started() == [] and box.told == []
    assert "102 (zigbee) died on its own" in capsys.readouterr().out


def test_message_language(box, monkeypatch):
    monkeypatch.setenv("GW_LANG", "ru")
    box.ct("102", "hostname: zigbee\nonboot: 1\n")
    gw.main()
    assert "упал сам" in box.told[0]
