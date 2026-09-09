"""Unit tests for Netstat Parser."""
from pathlib import Path
import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.netstat import NetstatParser
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


def test_netstat_parser_ss(tmp_path, ctx):
    ss_file = tmp_path / "ss.txt"
    ss_file.write_text(
        "Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              Process\n"
        "tcp    ESTAB      0      0      192.168.197.1:22                 192.168.197.2:53245               users:((\"sshd\",pid=1234,fd=3))\n"
        "tcp    LISTEN     0      128    0.0.0.0:22                       0.0.0.0:*                         users:((\"sshd\",pid=900,fd=3))\n"
        "udp    UNCONN     0      0      0.0.0.0:68                       0.0.0.0:*                         users:((\"dhclient\",pid=800,fd=5))\n",
        encoding="utf-8",
    )
    parser = NetstatParser()
    ctx.artifact_rel = "volatile/ss.txt"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version

    events = list(parser.parse(ss_file, ctx))
    assert len(events) == 3
    for ev in events:
        assert validate(ev) == []
        assert ev.category == "network_config"

    # ESTAB
    assert events[0].subcategory == "established"
    assert events[0].source_ip == "192.168.197.2"
    assert events[0].actor_process == "sshd"
    assert "192.168.197.1:22" in events[0].description

    # LISTEN
    assert events[1].subcategory == "listen"
    assert events[1].source_ip is None
    assert events[1].actor_process == "sshd"

    # UNCONN
    assert events[2].subcategory == "unconn"
    assert events[2].actor_process == "dhclient"


def test_netstat_parser_netstat(tmp_path, ctx):
    netstat_file = tmp_path / "netstat.txt"
    netstat_file.write_text(
        "Active Internet connections (servers and established)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      900/sshd\n"
        "tcp        0      0 192.168.197.1:22        192.168.197.2:53245     ESTABLISHED 1234/sshd\n"
        "udp        0      0 0.0.0.0:68              0.0.0.0:*                           800/dhclient\n",
        encoding="utf-8",
    )
    parser = NetstatParser()
    ctx.artifact_rel = "volatile/netstat.txt"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version

    events = list(parser.parse(netstat_file, ctx))
    assert len(events) == 3
    for ev in events:
        assert validate(ev) == []
        assert ev.category == "network_config"

    # LISTEN
    assert events[0].subcategory == "listen"
    assert events[0].source_ip is None
    assert events[0].actor_process == "sshd"

    # ESTABLISHED
    assert events[1].subcategory == "established"
    assert events[1].source_ip == "192.168.197.2"
    assert events[1].actor_process == "sshd"

    # UNCONN (udp with no state)
    assert events[2].subcategory == "unconn"
    assert events[2].actor_process == "dhclient"
