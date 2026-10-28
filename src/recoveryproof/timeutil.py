"""Timestamp helpers.

All timestamps inside RecoveryProof are timezone-aware and normalised to UTC.
Naive datetimes are rejected at the schema boundary so that RPO and freshness
calculations can never silently mix local time with UTC.
"""

from __future__ import annotations

from datetime import UTC, datetime


def to_utc(value: datetime) -> datetime:
    """Normalise an aware datetime to UTC; reject naive datetimes."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone offset (e.g. 'Z' or '+00:00')")
    return value.astimezone(UTC)


def minutes_between(start: datetime, end: datetime) -> int:
    """Whole minutes from ``start`` to ``end`` (floored; negative if end < start)."""
    seconds = (to_utc(end) - to_utc(start)).total_seconds()
    return int(seconds // 60)


def fmt_minutes(minutes: int | None, unknown: str = "Unknown") -> str:
    """Human readable duration, e.g. ``1 d 2 h``, ``2 h 15 min``, ``45 min``."""
    if minutes is None:
        return unknown
    sign = "-" if minutes < 0 else ""
    m = abs(minutes)
    days, rem = divmod(m, 1440)
    hours, mins = divmod(rem, 60)
    if days:
        parts = [f"{days} d"] + ([f"{hours} h"] if hours else []) + ([f"{mins} min"] if mins else [])
        return sign + " ".join(parts)
    if hours:
        return f"{sign}{hours} h {mins} min" if mins else f"{sign}{hours} h"
    return f"{sign}{mins} min"


def fmt_ts(value: datetime | None, unknown: str = "Unknown") -> str:
    """Format a timestamp as ``YYYY-MM-DD HH:MM UTC``."""
    if value is None:
        return unknown
    return to_utc(value).strftime("%Y-%m-%d %H:%M UTC")


def utc_now() -> datetime:
    return datetime.now(UTC)
