"""Plain-dict serialization for SQLAlchemy rows returned straight from routes.

FastAPI's default encoder walks an ORM instance's __dict__, which is empty or
partial for expired/refreshed rows -- endpoints that `return job` then answer
200 with `{}`-ish bodies. Serialize columns explicitly instead.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Any, Iterable, List

from sqlalchemy import inspect as sa_inspect


def orm_dict(obj: Any) -> dict:
    if obj is None:
        return None  # type: ignore[return-value]
    out = {}
    for col in sa_inspect(obj).mapper.column_attrs:
        v = getattr(obj, col.key)
        out[col.key] = v.isoformat() if isinstance(v, (datetime, date)) else v
    return out


def orm_list(objs: Iterable[Any]) -> List[dict]:
    return [orm_dict(o) for o in objs]
