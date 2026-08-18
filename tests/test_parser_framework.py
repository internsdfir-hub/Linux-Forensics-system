"""Parser plugin framework (spec 2.6.1): auto-discovery, per-plugin error
isolation, per-artifact success/fail/skip stats for the methodology section."""
from pathlib import Path

from lfa.parsers.base import BaseParser, ParserRun, discover_parsers
from lfa.schema import make_event


def test_discovers_shipped_parsers():
    parsers = discover_parsers()
    names = {p.name for p in parsers}
    # the registry finds at least the environment parser (first real plugin)
    assert "env_parser" in names
    for p in parsers:
        assert p.name and p.version and p.artifact_category
        assert isinstance(p.applies_to, list)


class _BoomParser(BaseParser):
    name = "boom_parser"
    version = "1.0"
    artifact_category = "login_activity"
    applies_to = ["var/log/boom*"]

    def parse(self, path, context):
        yield from ()
        raise RuntimeError("deliberate parser explosion")


class _OkParser(BaseParser):
    name = "ok_parser"
    version = "1.0"
    artifact_category = "login_activity"
    applies_to = ["var/log/ok*"]

    def parse(self, path, context):
        yield context.build_event(
            event_kind="event",
            timestamp_utc="2024-03-14T02:19:07+00:00",
            timestamp_local="2024-03-14T07:19:07+05:00",
            timestamp_confidence="exact",
            category="login_activity",
            subcategory="test",
            description="ok",
            severity="info",
            raw_line="ok line",
            raw_line_offset=0,
        )


def _ctx(tmp_path):
    from lfa.parsers.base import ParseContext
    from lfa.timeeng import TimeContext

    return ParseContext(
        case_id="C1",
        host_id="H1",
        raw_host_dir=tmp_path,
        time_ctx=TimeContext("Asia/Karachi", "etc_localtime"),
        distro_profile={"distro_id": "debian"},
        artifact_rel="var/log/ok.1",
        artifact_sha256="f" * 64,
        tool_generated_flag=False,
    )


def test_crashing_parser_is_isolated_and_logged(tmp_path):
    (tmp_path / "var/log").mkdir(parents=True)
    boom_file = tmp_path / "var/log/boom.1"
    boom_file.write_text("x\n")
    ok_file = tmp_path / "var/log/ok.1"
    ok_file.write_text("y\n")

    run = ParserRun(parsers=[_BoomParser(), _OkParser()], errors_log=tmp_path / "parser_errors.log")
    ctx = _ctx(tmp_path)
    events_boom = run.parse_artifact(boom_file, "var/log/boom.1", ctx)
    events_ok = run.parse_artifact(ok_file, "var/log/ok.1", ctx)

    assert events_boom == []
    assert len(events_ok) == 1
    stats = run.stats
    assert stats["boom_parser"]["fail"] == 1
    assert stats["ok_parser"]["success"] == 1
    log_text = (tmp_path / "parser_errors.log").read_text()
    assert "deliberate parser explosion" in log_text
    assert "Traceback" in log_text


def test_no_parser_claims_artifact_counts_as_skip(tmp_path):
    (tmp_path / "var/log").mkdir(parents=True)
    odd = tmp_path / "var/log/unclaimed.bin"
    odd.write_bytes(b"\x00")
    run = ParserRun(parsers=[_OkParser()], errors_log=tmp_path / "parser_errors.log")
    events = run.parse_artifact(odd, "var/log/unclaimed.bin", _ctx(tmp_path))
    assert events == []
    assert run.skipped == ["var/log/unclaimed.bin"]


def test_context_build_event_fills_provenance(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.parser_name = "ok_parser"
    ctx.parser_version = "1.0"
    ev = ctx.build_event(
        event_kind="event",
        timestamp_utc="2024-03-14T02:19:07+00:00",
        timestamp_local="2024-03-14T07:19:07+05:00",
        timestamp_confidence="exact",
        category="login_activity",
        subcategory="test",
        description="d",
        severity="info",
        raw_line="r",
        raw_line_offset=5,
    )
    assert ev.case_id == "C1"
    assert ev.host_id == "H1"
    assert ev.source_artifact_path == "var/log/ok.1"
    assert ev.source_artifact_sha256 == "f" * 64
    assert ev.parser_name == "ok_parser"
    assert ev.timestamp_tz == "Asia/Karachi"
    assert ev.tz_source == "etc_localtime"
    from lfa.schema import validate

    assert validate(ev) == []
