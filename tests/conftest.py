import pytest

from lfa.schema import make_event


@pytest.fixture
def event_factory():
    """Build valid NormalizedEvents with minimal boilerplate in tests."""

    def _make(**overrides):
        kw = dict(
            case_id="CASE-001",
            host_id="host-abc",
            event_kind="event",
            timestamp_utc="2024-03-14T02:19:07+00:00",
            timestamp_local="2024-03-14T07:19:07+05:00",
            timestamp_tz="Asia/Karachi",
            tz_source="etc_localtime",
            timestamp_confidence="exact",
            category="login_activity",
            subcategory="failed_login",
            actor_user="admin",
            actor_uid=1000,
            actor_process="sshd",
            source_ip="203.0.113.9",
            source_host=None,
            description="Failed password for admin from 203.0.113.9",
            severity="low",
            source_artifact_path="var/log/auth.log",
            source_artifact_sha256="a" * 64,
            raw_line="Mar 14 02:19:07 web1 sshd[123]: Failed password ...",
            raw_line_offset=1024,
            parser_name="authlog_parser",
            parser_version="1.0",
            tool_generated_flag=False,
            notes=None,
        )
        kw.update(overrides)
        return make_event(**kw)

    return _make
