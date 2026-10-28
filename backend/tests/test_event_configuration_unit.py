"""Pure M2-03 validation, including time-zone and schema attack cases."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.events.service import (
    EventInvalid,
    readiness,
    utc,
    validate_form,
    validate_timezone,
    validate_windows,
)


def test_import_only_event_publishes_without_public_registration_window() -> None:
    event = SimpleNamespace(
        registration_mode="import_only",
        registration_opens_at=None,
        registration_closes_at=None,
        checkin_opens_at=datetime.now(UTC) - timedelta(minutes=1),
        checkin_closes_at=datetime.now(UTC) + timedelta(days=1),
        ends_at=datetime.now(UTC) + timedelta(days=1),
        form_schema={"fields": []},
    )
    assert readiness(event, 2) == []
    event.registration_mode = "public"
    assert "Set registration opening and closing dates." in readiness(event, 2)


def test_form_schema_bounds_and_injection() -> None:
    assert validate_form({"fields": []}) == {"fields": []}
    assert validate_form(
        {
            "fields": [
                {
                    "key": "meal",
                    "label": "Meal preference",
                    "type": "select",
                    "required": False,
                    "options": ["Vegan", "Other"],
                },
            ]
        }
    )["fields"]
    for schema in (
        {"fields": [{"key": "email", "label": "Email", "type": "text", "required": True}]},
        {
            "fields": [
                {
                    "key": "note",
                    "label": "<script>alert(1)</script>",
                    "type": "text",
                    "required": False,
                    "html": "<script>",
                }
            ]
        },
        {
            "fields": [
                {
                    "key": "note",
                    "label": "<script>alert(1)</script>",
                    "type": "text",
                    "required": False,
                }
            ]
        },
        {
            "fields": [
                {
                    "key": "x",
                    "label": "X",
                    "type": "select",
                    "required": False,
                    "options": ["Same", "Same"],
                }
            ]
        },
        {"fields": [{"key": "x", "label": "X", "type": "text", "required": False}] * 31},
    ):
        with pytest.raises(EventInvalid):
            validate_form(schema)


def test_explicit_offsets_utc_and_dst_window() -> None:
    assert validate_timezone("Africa/Lagos") == "Africa/Lagos"
    assert validate_timezone("America/New_York") == "America/New_York"
    with pytest.raises(EventInvalid):
        validate_timezone("Mars/Phobos")
    with pytest.raises(EventInvalid):
        utc(datetime(2026, 11, 1, 1, 30))
    # Both occurrences of 01:30 on a fall-back day represent distinct instants.
    first = datetime.fromisoformat("2026-11-01T01:30:00-04:00")
    second = datetime.fromisoformat("2026-11-01T01:30:00-05:00")
    assert utc(second) - utc(first) == timedelta(hours=1)
    validate_windows(first, second, first - timedelta(days=1), first, first, second)
    with pytest.raises(EventInvalid):
        validate_windows(first, second, None, first, first, second)
    with pytest.raises(EventInvalid):
        validate_windows(first, second, first, second + timedelta(hours=1), first, second)
    with pytest.raises(EventInvalid):
        validate_windows(first, second, None, None, first - timedelta(hours=4, seconds=1), second)
    with pytest.raises(EventInvalid):
        validate_windows(
            datetime.now(UTC), datetime.now(UTC) - timedelta(hours=1), None, None, None, None
        )


@pytest.mark.parametrize("hours", [0, 2, 4])
def test_checkin_can_open_before_event(hours: int) -> None:
    start = datetime(2026, 11, 1, 12, tzinfo=UTC)
    validate_windows(
        start,
        start + timedelta(hours=3),
        None,
        None,
        start - timedelta(hours=hours),
        start + timedelta(hours=3),
    )


@pytest.mark.parametrize(
    "opening,closing",
    [
        (timedelta(hours=-4, seconds=-1), timedelta(hours=1)),
        (timedelta(hours=-4), timedelta(hours=3, seconds=1)),
        (timedelta(hours=1), timedelta(hours=1)),
    ],
)
def test_checkin_window_boundaries_remain_enforced(opening, closing) -> None:
    start = datetime(2026, 11, 1, 12, tzinfo=UTC)
    with pytest.raises(EventInvalid):
        validate_windows(
            start, start + timedelta(hours=3), None, None, start + opening, start + closing
        )
