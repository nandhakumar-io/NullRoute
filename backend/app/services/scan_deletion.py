"""Deleting scans (single + bulk).

A Scan is referenced by ~20 tables. Rather than hand-maintain a list that goes
stale every time someone adds a ``scan_id`` column, this walks the SQLAlchemy
metadata for every foreign key that points at ``scans.id`` and applies one
rule per column:

  * nullable FK  -> the referencing row is KEPT and detached (set to NULL).
    This is what keeps evidence records, topology snapshots, alerts,
    deployment / rollback records and training examples: they're audit or
    operational history that must outlive the scan they came from
    (evidence in particular is immutable -- RULE 15).
  * NOT NULL FK  -> the row cannot exist without the scan, so it is deleted
    (findings, OPA / Batfish / AI analyses, report artifacts, drift rows,
    backup jobs, golden-baseline approvals ...), recursing into anything that
    in turn references *those* rows.

Golden baselines are protected: deleting a scan that is a device's approved
baseline needs ``force``.
"""
from __future__ import annotations

import logging
from typing import Iterable, List, Sequence, Tuple

from sqlalchemy import bindparam, delete, select, update
from sqlalchemy.orm import Session
from sqlalchemy.sql import text
from sqlalchemy.sql.schema import Column, Table

import app.models.backup  # noqa: F401  - make sure every model is on Base.metadata
from app.models.db import Base, BaselineApproval, Finding, RagDocument, Scan

log = logging.getLogger("scan_deletion")

_CHUNK = 400  # stay well under SQLite's 999 bound-variable limit


def _chunks(values: Sequence[str]):
    for i in range(0, len(values), _CHUNK):
        yield list(values[i:i + _CHUNK])


def _referrers(target: Table) -> List[Column]:
    """Every column in the metadata with a FK to ``target``'s primary key."""
    pk_cols = list(target.primary_key.columns)
    if len(pk_cols) != 1:
        return []
    pk = pk_cols[0]
    cols: List[Column] = []
    for table in Base.metadata.tables.values():
        if table is target:
            continue
        for fk in table.foreign_keys:
            if fk.column is pk:
                cols.append(fk.parent)
    return cols


def _delete_where(db: Session, table: Table, col: Column, values: Sequence[str]) -> None:
    """DELETE FROM table WHERE col IN values, first detaching/removing whatever
    references those rows."""
    pk_cols = list(table.primary_key.columns)
    if len(pk_cols) == 1:
        pk = pk_cols[0]
        ids = [r[0] for chunk in _chunks(values) for r in db.execute(select(pk).where(col.in_(chunk)))]
        for child_col in _referrers(table):
            for chunk in _chunks(ids):
                if child_col.nullable:
                    db.execute(update(child_col.table).where(child_col.in_(chunk)).values({child_col.name: None}))
                else:
                    _delete_where(db, child_col.table, child_col, chunk)
    for chunk in _chunks(values):
        db.execute(delete(table).where(col.in_(chunk)))


def golden_baseline_scan_ids(db: Session, scan_ids: Sequence[str]) -> List[str]:
    found: List[str] = []
    for chunk in _chunks(scan_ids):
        found.extend(r[0] for r in db.query(BaselineApproval.scan_id).filter(BaselineApproval.scan_id.in_(chunk)))
    return found


def purge_scans(db: Session, scan_ids: Iterable[str]) -> None:
    """Delete the scans and everything that can't outlive them. Does NOT
    commit -- the caller owns the transaction so a failure rolls back cleanly."""
    ids = list(dict.fromkeys(scan_ids))
    if not ids:
        return

    # RAG chunks indexed from this scan's findings would otherwise keep
    # answering chat questions about findings that no longer exist.
    finding_ids: List[str] = []
    for chunk in _chunks(ids):
        finding_ids.extend(r[0] for r in db.query(Finding.id).filter(Finding.scan_id.in_(chunk)))
    for chunk in _chunks(finding_ids):
        db.execute(delete(RagDocument).where(RagDocument.source_type == "finding", RagDocument.source_id.in_(chunk)))

    scans_table: Table = Scan.__table__
    for child_col in _referrers(scans_table):
        for chunk in _chunks(ids):
            if child_col.nullable:
                db.execute(update(child_col.table).where(child_col.in_(chunk)).values({child_col.name: None}))
            else:
                _delete_where(db, child_col.table, child_col, chunk)

    # Legacy table that isn't an ORM model in every deployment.
    for chunk in _chunks(ids):
        try:
            with db.begin_nested():
                stmt = text("DELETE FROM scan_audits WHERE scan_id IN :ids").bindparams(bindparam("ids", expanding=True))
                db.execute(stmt, {"ids": chunk})
        except Exception:  # noqa: BLE001 - table may not exist
            pass

    for chunk in _chunks(ids):
        db.execute(delete(scans_table).where(scans_table.c.id.in_(chunk)))
