"""
Database layer.

Dev default: SQLite (zero external services, works out of the box with
`docker compose up`). Production: point DATABASE_URL at Postgres, e.g.
postgresql+asyncpg://user:pass@db:5432/ctfcopilot -- the models below are
plain SQLAlchemy and work unchanged against either backend.
"""
import os
import uuid
import datetime as dt

from sqlalchemy import String, Text, Float, DateTime, ForeignKey, JSON
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./data/ctfcopilot.db")

os.makedirs("./data", exist_ok=True)

engine = create_async_engine(DATABASE_URL, echo=False)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class Challenge(Base):
    __tablename__ = "challenges"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    target_scope: Mapped[str] = mapped_column(String(32), default="LOCAL_ARTIFACT")
    status: Mapped[str] = mapped_column(String(32), default="created")
    category_scores: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)

    artifacts: Mapped[list["Artifact"]] = relationship(back_populates="challenge", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="challenge", cascade="all, delete-orphan")
    tool_runs: Mapped[list["ToolExecution"]] = relationship(back_populates="challenge", cascade="all, delete-orphan")
    flag_candidates: Mapped[list["FlagCandidate"]] = relationship(back_populates="challenge", cascade="all, delete-orphan")


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    challenge_id: Mapped[str] = mapped_column(ForeignKey("challenges.id"))
    kind: Mapped[str] = mapped_column(String(32))  # file | url
    name: Mapped[str] = mapped_column(String(512))
    path: Mapped[str] = mapped_column(String(1024), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    mime: Mapped[str] = mapped_column(String(128), default="")
    size: Mapped[int] = mapped_column(default=0)

    challenge: Mapped["Challenge"] = relationship(back_populates="artifacts")


class ToolExecution(Base):
    __tablename__ = "tool_executions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    challenge_id: Mapped[str] = mapped_column(ForeignKey("challenges.id"))
    tool: Mapped[str] = mapped_column(String(64))
    input_summary: Mapped[str] = mapped_column(Text, default="")
    output_summary: Mapped[str] = mapped_column(Text, default="")
    success: Mapped[bool] = mapped_column(default=True)
    duration_ms: Mapped[int] = mapped_column(default=0)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)

    challenge: Mapped["Challenge"] = relationship(back_populates="tool_runs")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    challenge_id: Mapped[str] = mapped_column(ForeignKey("challenges.id"))
    severity: Mapped[str] = mapped_column(String(32), default="info")
    message: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)

    challenge: Mapped["Challenge"] = relationship(back_populates="findings")


class FlagCandidate(Base):
    __tablename__ = "flag_candidates"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    challenge_id: Mapped[str] = mapped_column(ForeignKey("challenges.id"))
    candidate: Mapped[str] = mapped_column(String(600))
    source: Mapped[str] = mapped_column(String(128), default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(32), default="UNCONFIRMED")
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)

    challenge: Mapped["Challenge"] = relationship(back_populates="flag_candidates")


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session
