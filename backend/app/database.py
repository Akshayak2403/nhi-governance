"""
Database engine/session setup.

Uses SQLAlchemy so the underlying database is swappable. By default this
points at a local SQLite file for zero-friction local dev/demo, but it is
driven entirely off the DATABASE_URL env var -- pointing that at Postgres
(the preferred DB per the requirements) requires no code changes:

    export DATABASE_URL="postgresql+psycopg2://user:pass@host:5432/nhi_gov"

See README.md "Switching to PostgreSQL" for exact steps.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./nhi_governance.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
