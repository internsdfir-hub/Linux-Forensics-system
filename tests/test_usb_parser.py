"""USB kernel-message parser (spec category 6, trap #9).

A single USB insertion is spread over six or more kernel lines: the speed
line, idVendor/idProduct, the string indices, then Product, Manufacturer and
SerialNumber - each keyed only by the `usb 1-2` bus-port id. A line-at-a-time
parser produces six useless fragments; the analyst needs ONE event that says
"SanDisk Cruzer Blade, serial 4C53..., plugged in at 02:41 and pulled out at
03:15 after 34 minutes".

So this parser keeps a small stateful buffer per bus-port id, stitches the
sequence into one connect event, matches the later `USB disconnect` line to
compute the connection duration, and flushes devices that were never
disconnected as still-attached.
"""
import gzip
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.usb import UsbParser
from lfa.schema import validate
from lfa.timeeng import TimeContext

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "system"
MTIME = datetime(2024, 3, 20, tzinfo=timezone.utc).timestamp()


@pytest.fixture
def ctx(tmp_path):
    return ParseContext(
        case_id="C1",
        host_id="H1",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("Asia/Karachi", "etc_localtime"),
        distro_profile={"distro_id": "debian"},
        artifact_sha256="a" * 64,
        artifact_mtime=MTIME,
    )


def parse(ctx, rel, root=FIXTURES):
    parser = UsbParser()
    ctx.artifact_rel = rel
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version
    events = list(parser.parse(Path(root) / rel, ctx))
    for ev in events:
        assert validate(ev) == [], ev
        assert ev.category == "hardware_usb"
        assert ev.event_kind == "event"
    return events


def write(tmp_path, text, name="kern.log"):
    d = tmp_path / "var/log"
    d.mkdir(parents=True, exist_ok=True)
    target = d / name
    target.write_bytes(text if isinstance(text, bytes) else text.encode())
    return f"var/log/{name}"


def test_claims_kernel_message_logs():
    parser = UsbParser()
    for rel in (
        "var/log/kern.log", "var/log/kern.log.1", "var/log/kern.log.2.gz",
        "var/log/syslog", "var/log/syslog.1", "var/log/messages",
        "var/log/messages-20240310",
    ):
        assert parser.can_parse(rel, {}), rel
    assert not parser.can_parse("var/log/auth.log", {})


def test_multiline_sequence_stitched_into_one_connect(ctx):
    events = parse(ctx, "var/log/kern.log")
    connects = [e for e in events if e.subcategory == "usb_connect"]
    assert len(connects) == 2
    stick = next(e for e in connects if "1-2" in e.description)
    for token in ("0781", "5567", "SanDisk", "Cruzer Blade",
                  "4C530001120523104381"):
        assert token in stick.description, token
    assert stick.timestamp_confidence == "year_inferred"
    assert stick.timestamp_local == "2024-03-14T02:41:03+05:00"


def test_root_hub_noise_is_ignored(ctx):
    events = parse(ctx, "var/log/kern.log")
    assert not any("usb1:" in e.description for e in events)


def test_disconnect_event_carries_duration(ctx):
    events = parse(ctx, "var/log/kern.log")
    disconnects = [e for e in events if e.subcategory == "usb_disconnect"]
    assert len(disconnects) == 1
    off = disconnects[0]
    assert off.timestamp_local == "2024-03-14T03:15:44+05:00"
    # 02:41:03 -> 03:15:44 is 34 minutes 41 seconds
    assert "34m 41s" in off.description
    assert "34m 41s" in (off.notes or "")
    assert "SanDisk" in off.description


def test_removable_storage_raises_severity(ctx):
    events = parse(ctx, "var/log/kern.log")
    stick = next(e for e in events
                 if e.subcategory == "usb_connect" and "1-2" in e.description)
    receiver = next(e for e in events
                    if e.subcategory == "usb_connect" and "1-4" in e.description)
    assert stick.severity == "medium"
    assert "storage" in (stick.notes or "").lower()
    assert receiver.severity == "info"


def test_device_never_disconnected_is_reported_as_still_attached(ctx):
    events = parse(ctx, "var/log/kern.log")
    receiver = next(e for e in events
                    if e.subcategory == "usb_connect" and "1-4" in e.description)
    assert "Logitech" in receiver.description
    assert "still attached" in (receiver.notes or "").lower()


def test_disconnect_without_matching_connect_is_still_reported(ctx, tmp_path):
    rel = write(tmp_path,
                "Mar 14 03:15:44 web1 kernel: [14000.0] usb 2-1: "
                "USB disconnect, device number 9\n")
    events = parse(ctx, rel, root=tmp_path)
    assert len(events) == 1
    assert events[0].subcategory == "usb_disconnect"
    assert "no matching" in (events[0].notes or "").lower()


def test_replug_of_same_port_yields_two_connects(ctx, tmp_path):
    rel = write(tmp_path, (
        "Mar 14 01:00:00 web1 kernel: usb 1-2: new high-speed USB device number 3 using xhci_hcd\n"
        "Mar 14 01:00:00 web1 kernel: usb 1-2: New USB device found, idVendor=0781, idProduct=5567, bcdDevice= 1.00\n"
        "Mar 14 02:00:00 web1 kernel: usb 1-2: new high-speed USB device number 4 using xhci_hcd\n"
        "Mar 14 02:00:00 web1 kernel: usb 1-2: New USB device found, idVendor=1234, idProduct=5678, bcdDevice= 1.00\n"
    ))
    events = parse(ctx, rel, root=tmp_path)
    connects = [e for e in events if e.subcategory == "usb_connect"]
    assert len(connects) == 2
    assert {"0781", "1234"} <= {t for e in connects for t in e.description.split()}


def test_gzip_rotation_is_transparent(ctx, tmp_path):
    src = (FIXTURES / "var/log/kern.log").read_bytes()
    d = tmp_path / "var/log"
    d.mkdir(parents=True)
    (d / "kern.log.2.gz").write_bytes(gzip.compress(src))
    events = parse(ctx, "var/log/kern.log.2.gz", root=tmp_path)
    assert len([e for e in events if e.subcategory == "usb_connect"]) == 2


def test_truncated_and_binary_input_does_not_raise(ctx, tmp_path):
    rel = write(tmp_path, (
        b"\x00\x01\xff\xfe not a log line\n"
        b"Mar 14 02:41:03 web1 kernel: usb 1-2: new high-speed USB device numbe"
        b"\nMar 14 02:41:03 web1 kernel: usb 1-2: New USB device found, idVendor=0781\n"
        b"no timestamp at all: usb 3-1: USB disconnect, device number 2\n"
    ))
    events = parse(ctx, rel, root=tmp_path)
    for ev in events:
        if ev.timestamp_utc is None:
            assert ev.timestamp_confidence == "unknown"


def test_log_without_usb_lines_is_quiet(ctx, tmp_path):
    rel = write(tmp_path,
                "Mar 14 02:41:03 web1 kernel: [12345.0] EXT4-fs: mounted\n")
    assert parse(ctx, rel, root=tmp_path) == []
