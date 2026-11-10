import uuid
from collections.abc import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session, SessionTransaction, sessionmaker

from app.core.config import get_settings

_settings = get_settings()

engine = create_engine(
    _settings.database_url,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def _apply_rls_on_connection(
    connection: Connection,
    tenant_id_str: str | None,
    user_id_str: str | None,
) -> None:
    if tenant_id_str is not None:
        connection.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": tenant_id_str},
        )
    if user_id_str is not None:
        connection.execute(
            text("SELECT set_config('app.current_user_id', :uid, true)"),
            {"uid": user_id_str},
        )


@event.listens_for(Session, "after_begin")
def _on_session_after_begin(
    session: Session,
    transaction: SessionTransaction,  # noqa: ARG001
    connection: Connection,
) -> None:
    tenant_id_str = session.info.get("rls_tenant_id")
    user_id_str = session.info.get("rls_user_id")
    if tenant_id_str is not None or user_id_str is not None:
        _apply_rls_on_connection(connection, tenant_id_str, user_id_str)


def set_rls_context(
    session: Session,
    *,
    tenant_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    clear: bool = False,
) -> None:
    if clear:
        session.info["rls_tenant_id"] = ""
        session.info["rls_user_id"] = ""
    else:
        if tenant_id is not None:
            session.info["rls_tenant_id"] = str(tenant_id)
        if user_id is not None:
            session.info["rls_user_id"] = str(user_id)

    if session.in_transaction():
        tid = session.info.get("rls_tenant_id")
        uid = session.info.get("rls_user_id")
        if tid is not None:
            session.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": tid},
            )
        if uid is not None:
            session.execute(
                text("SELECT set_config('app.current_user_id', :uid, true)"),
                {"uid": uid},
            )


def get_db_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
