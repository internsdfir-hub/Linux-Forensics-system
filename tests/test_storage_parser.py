"""Unit tests for Storage & Hard Disk parser (fstab, lsblk, blkid, mount)."""
from pathlib import Path
import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.storage import StorageParser
from lfa.schema import validate
from lfa.timeeng import TimeContext


@pytest.fixture
def ctx(tmp_path):
    return ParseContext(
        case_id="CASE-01",
        host_id="HOST-01",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("UTC", "assumed_utc"),
        distro_profile={"distro_id": "ubuntu"},
        artifact_sha256="0" * 64,
        artifact_mtime=1700000000.0,
    )


def test_storage_parser_fstab(tmp_path, ctx):
    fstab_file = tmp_path / "fstab"
    fstab_file.write_text(
        "# /etc/fstab: static file system information.\n"
        "UUID=1111-2222 / ext4 errors=remount-ro 0 1\n"
        "/dev/sdb1 /mnt/backup ext4 defaults 0 2\n",
        encoding="utf-8",
    )
    parser = StorageParser()
    ctx.artifact_rel = "etc/fstab"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version

    events = list(parser.parse(fstab_file, ctx))
    assert len(events) == 2
    for ev in events:
        assert validate(ev) == []
        assert ev.category == "environment"
        assert ev.subcategory == "storage_device"

    assert "1111-2222" in events[0].description
    assert "/mnt/backup" in events[1].description


def test_storage_parser_blkid(tmp_path, ctx):
    blkid_file = tmp_path / "blkid.txt"
    blkid_file.write_text(
        '/dev/sda1: LABEL="cloudimg-rootfs" UUID="4c88a85f-89b5-4b36-a36a-200000000000" BLOCK_SIZE="4096" TYPE="ext4" PARTUUID="0001"\n'
        '/dev/sdb1: LABEL="USB_DATA" UUID="1234-5678" TYPE="vfat"\n',
        encoding="utf-8",
    )
    parser = StorageParser()
    ctx.artifact_rel = "volatile/blkid.txt"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version

    events = list(parser.parse(blkid_file, ctx))
    assert len(events) == 2
    for ev in events:
        assert validate(ev) == []
        assert ev.category == "environment"
    assert "cloudimg-rootfs" in events[0].description
    assert "USB_DATA" in events[1].description


def test_storage_parser_lsblk(tmp_path, ctx):
    lsblk_file = tmp_path / "lsblk.txt"
    lsblk_file.write_text(
        "NAME FSTYPE LABEL UUID FSAVAIL FSUSE% MOUNTPOINTS\n"
        "sda\n"
        "├─sda1 ext4 rootfs 4c88a85f-89b5 24.2G 45% /\n"
        "└─sda2 swap 5d92a85f-89b5 [SWAP]\n",
        encoding="utf-8",
    )
    parser = StorageParser()
    ctx.artifact_rel = "volatile/lsblk.txt"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version

    events = list(parser.parse(lsblk_file, ctx))
    assert len(events) >= 2
    for ev in events:
        assert validate(ev) == []
        assert ev.category == "environment"
