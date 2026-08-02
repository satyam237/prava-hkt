"""SQLite persistence for intents, verifications, warrants and Prava sessions.

Deliberately small: four tables, no migrations, no accounts. The only thing
that has to survive a page navigation is the evidence — a judge on the Record
screen must be able to pull back the exact signed document and the run that
produced it.

Rows are storage, not the wire format. ``app.models`` owns the wire format; a
row holds the already-serialized document plus the few columns worth querying
by. That keeps a schema change here from touching the signed bytes.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column
from sqlalchemy.engine import Engine
from sqlmodel import Field, Session, SQLModel, create_engine, select

from app.models import utcnow

DB_URL_ENV = "WARRANT_DB_URL"
DEFAULT_DB_URL = "sqlite:///warrant.db"


class IntentRecord(SQLModel, table=True):
    """What the user asked for, before any evidence exists."""

    __tablename__ = "intent"

    intent_id: str = Field(primary_key=True)
    reference: str
    domain: str = Field(index=True)
    host: str
    url: str
    source: str
    sku: str
    description: str
    quantity: int
    amount: str
    currency: str
    expected_fulfillment_by: datetime | None = None
    created_at: datetime = Field(default_factory=utcnow)


class VerificationRecord(SQLModel, table=True):
    """One verification run, whether it cleared or halted.

    A HALT has a record and no warrant. That asymmetry is the gate: there is
    nothing here to hand to the payment leg.
    """

    __tablename__ = "verification"

    verification_id: str = Field(primary_key=True)
    intent_id: str = Field(index=True)
    domain: str = Field(index=True)
    resolved_name: str | None = None
    verdict: str
    score: str
    content_hash: str
    #: Includes each probe's ``detail``, which is not part of the signed
    #: document but is the only human-readable reason a signal failed.
    signals: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    halt_reason: str | None = None
    warrant_id: str | None = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=utcnow)


class WarrantRecord(SQLModel, table=True):
    """An issued, signed WARRANT, stored as the exact document that was signed."""

    __tablename__ = "warrant"

    warrant_id: str = Field(primary_key=True)
    verification_id: str = Field(index=True)
    domain: str = Field(index=True)
    warrant_hash: str
    document: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    issued_at: datetime = Field(default_factory=utcnow)


class SessionRecord(SQLModel, table=True):
    """A Prava session requested against a cleared warrant.

    No credential is stored. ``iframe_url`` is single-use and expires in 15
    minutes; it is kept only so the Approval screen can be reloaded within that
    window, and it is never fetched server-side.
    """

    __tablename__ = "prava_session"

    session_id: str = Field(primary_key=True)
    warrant_id: str = Field(index=True)
    order_id: str | None = None
    iframe_url: str | None = None
    expires_at: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


_engine: Engine | None = None


def configure(url: str | None = None, *, engine: Engine | None = None) -> Engine:
    """Point the store at a database and create the tables."""

    global _engine
    if engine is None:
        target = url or os.environ.get(DB_URL_ENV) or DEFAULT_DB_URL
        # check_same_thread: FastAPI runs sync work in a threadpool, so a
        # connection is not guaranteed to be reused on its creating thread.
        connect_args = {"check_same_thread": False} if target.startswith("sqlite") else {}
        engine = create_engine(target, connect_args=connect_args)
    _engine = engine
    SQLModel.metadata.create_all(_engine)
    return _engine


def get_engine() -> Engine:
    return _engine if _engine is not None else configure()


def reset() -> None:
    """Drop the configured engine. Tests use this; nothing else should."""

    global _engine
    _engine = None


@contextmanager
def session() -> Iterator[Session]:
    # expire_on_commit=False: getters return rows for use after the short-lived
    # session closes (API handlers read attributes outside the with-block).
    with Session(get_engine(), expire_on_commit=False) as db:
        yield db


def save(*records: SQLModel) -> None:
    with session() as db:
        for record in records:
            db.add(record)
        db.commit()


def get_intent(intent_id: str) -> IntentRecord | None:
    with session() as db:
        record = db.get(IntentRecord, intent_id)
        if record is not None:
            db.expunge(record)
        return record


def get_verification(verification_id: str) -> VerificationRecord | None:
    with session() as db:
        record = db.get(VerificationRecord, verification_id)
        if record is not None:
            db.expunge(record)
        return record


def get_warrant(warrant_id: str) -> WarrantRecord | None:
    with session() as db:
        record = db.get(WarrantRecord, warrant_id)
        if record is not None:
            db.expunge(record)
        return record


def get_verification_for_warrant(warrant_id: str) -> VerificationRecord | None:
    with session() as db:
        statement = select(VerificationRecord).where(VerificationRecord.warrant_id == warrant_id)
        record = db.exec(statement).first()
        if record is not None:
            db.expunge(record)
        return record


__all__ = [
    "DB_URL_ENV",
    "DEFAULT_DB_URL",
    "IntentRecord",
    "SessionRecord",
    "VerificationRecord",
    "WarrantRecord",
    "configure",
    "get_engine",
    "get_intent",
    "get_verification",
    "get_verification_for_warrant",
    "get_warrant",
    "reset",
    "save",
    "session",
]
