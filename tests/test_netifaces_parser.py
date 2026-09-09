"""Unit tests for Network Interfaces parser (interfaces, netplan, ip addr)."""
from pathlib import Path
import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.netifaces import NetIfacesParser
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


def test_netifaces_parser_ip_addr(tmp_path, ctx):
    ip_file = tmp_path / "ip_addr.txt"
    ip_file.write_text(
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n"
        "    link/ether 00:0c:29:4f:8e:35 brd ff:ff:ff:ff:ff:ff\n"
        "    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\n",
        encoding="utf-8",
    )
    parser = NetIfacesParser()
    ctx.artifact_rel = "volatile/ip_addr.txt"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version

    events = list(parser.parse(ip_file, ctx))
    assert len(events) == 2
    for ev in events:
        assert validate(ev) == []
        assert ev.category == "network_config"
        assert ev.subcategory == "network_interface"

    assert "127.0.0.1" in events[0].description
    assert "192.168.1.100" in events[1].description
    assert events[1].source_ip == "192.168.1.100"


def test_netifaces_parser_interfaces(tmp_path, ctx):
    iface_file = tmp_path / "interfaces"
    iface_file.write_text(
        "auto eth0\n"
        "iface eth0 inet static\n"
        "    address 10.0.2.15\n"
        "    netmask 255.255.255.0\n"
        "    gateway 10.0.2.2\n",
        encoding="utf-8",
    )
    parser = NetIfacesParser()
    ctx.artifact_rel = "etc/network/interfaces"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version

    events = list(parser.parse(iface_file, ctx))
    assert len(events) == 1
    ev = events[0]
    assert validate(ev) == []
    assert ev.source_ip == "10.0.2.15"
    assert "10.0.2.15" in ev.description
