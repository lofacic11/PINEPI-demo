from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar

from .db import Database


class EventLog:
    _levels: ClassVar[frozenset[str]] = frozenset({"DEBUG", "INFO", "WARNING", "ERROR"})

    def __init__(self, database: Database):
        self.database = database

    def write(self, level: str, component: str, event: str, message: str, **context: Any) -> None:
        normalized = level.upper()
        if normalized not in self._levels:
            normalized = "INFO"
        # Callers pass identifiers and outcomes only. Credentials must never enter context.
        context.pop("password", None)
        context.pop("passphrase", None)
        self.database.insert_event(
            datetime.now(UTC).isoformat(), normalized, component.lower(), event, message, context
        )

    def list(self, level: str | None = None, component: str | None = None, search: str | None = None, limit: int = 500) -> list[dict]:
        clauses: list[str] = []
        params: list[Any] = []
        if level:
            clauses.append("level = ?")
            params.append(level.upper())
        if component:
            clauses.append("component = ?")
            params.append(component.lower())
        if search:
            clauses.append("(message LIKE ? OR event LIKE ?)")
            value = f"%{search[:100]}%"
            params.extend((value, value))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(min(max(limit, 1), 1000))
        return self.database.fetchall(
            f"SELECT id,timestamp,level,component,event,message,context_json FROM events{where} ORDER BY id DESC LIMIT ?",
            tuple(params),
        )
