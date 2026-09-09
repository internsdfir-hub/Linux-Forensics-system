"""Unit tests for DNS Parser (resolv.conf and /etc/hosts)."""
from pathlib import Path
import pytest

from lfa.parsers.base import ParseContext
from lfa.parsers.dns import DnsParser
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


def test_dns_parser_resolv_conf(tmp_path, ctx):
    res_file = tmp_path / "resolv.conf"
    res_file.write_text(
        "# Dynamic resolv.conf\n"
        "search localdomain corp.internal\n"
        "nameserver 192.168.197.2\n"
        "nameserver 8.8.8.8\n",
        encoding="utf-8",
    )
    parser = DnsParser()
    ctx.artifact_rel = "etc/resolv.conf"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version

    events = list(parser.parse(res_file, ctx))
    assert len(events) == 3
    for ev in events:
        assert validate(ev) == []
        assert ev.category == "network_config"

    # Search domain
    assert events[0].subcategory == "dns_search"
    assert "localdomain corp.internal" in events[0].description

    # Nameservers
    assert events[1].subcategory == "dns_nameserver"
    assert events[1].source_ip == "192.168.197.2"
    assert events[2].source_ip == "8.8.8.8"


def test_dns_parser_hosts(tmp_path, ctx):
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text(
        "127.0.0.1 localhost\n"
        "127.0.1.1 metasploitable.localdomain metasploitable\n"
        "192.168.1.50 fileserver\n",
        encoding="utf-8",
    )
    parser = DnsParser()
    ctx.artifact_rel = "etc/hosts"
    ctx.parser_name = parser.name
    ctx.parser_version = parser.version

    events = list(parser.parse(hosts_file, ctx))
    assert len(events) == 3
    for ev in events:
        assert validate(ev) == []
        assert ev.category == "network_config"
        assert ev.subcategory == "dns_mapping"

    assert events[0].source_ip == "127.0.0.1"
    assert events[1].source_ip == "127.0.1.1"
    assert events[2].source_ip == "192.168.1.50"
    assert "fileserver" in events[2].description
