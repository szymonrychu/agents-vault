import uuid

import psycopg
import pytest
from agents_common.db.migrate import run_migrations

PACKAGE = "agents_vault"


def add_entry(conn, name="DB_PASSWORD", **cols) -> uuid.UUID:
    values = {"name": name, "description": "d", **cols}
    names = ", ".join(values)
    marks = ", ".join(["%s"] * len(values))
    return conn.execute(
        f"INSERT INTO entries ({names}) VALUES ({marks}) RETURNING id", tuple(values.values())
    ).fetchone()[0]


def test_applies_twice_idempotent(empty_db_url):
    assert run_migrations(empty_db_url, PACKAGE) == ["0001_vault.sql"]
    assert run_migrations(empty_db_url, PACKAGE) == []
    with psycopg.connect(empty_db_url) as conn:
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            )
        }
    assert {"entries", "versions", "pins", "events"} <= tables


def test_version_state_check_rejects_unknown(conn):
    entry = add_entry(conn)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "INSERT INTO versions (entry_id, version, state) VALUES (%s, 1, 'x')", (entry,)
        )
    for n, state in enumerate(("writing", "live", "retired"), start=1):
        conn.execute(
            "INSERT INTO versions (entry_id, version, state) VALUES (%s, %s, %s)", (entry, n, state)
        )


def test_live_name_is_unique_until_deleted(conn):
    first = add_entry(conn)
    with pytest.raises(psycopg.errors.UniqueViolation):
        add_entry(conn)
    conn.execute("UPDATE entries SET deleted_at = now() WHERE id = %s", (first,))
    add_entry(conn)


@pytest.mark.parametrize("name", ["lower", "1ABC", "A-B", "", "A" * 129])
def test_entry_name_check(conn, name):
    with pytest.raises(psycopg.errors.CheckViolation):
        add_entry(conn, name=name)


def test_entry_name_check_accepts_valid(conn):
    add_entry(conn, name="_X9")
    add_entry(conn, name="A" * 128)


@pytest.mark.parametrize("description", ["", "x" * 501])
def test_description_length_check(conn, description):
    with pytest.raises(psycopg.errors.CheckViolation):
        add_entry(conn, description=description)


def test_event_actor_check(conn):
    for actor in ("user", "orchestrator", "sweeper"):
        conn.execute("INSERT INTO events (kind, actor) VALUES ('k', %s)", (actor,))
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("INSERT INTO events (kind, actor) VALUES ('k', 'agent')")


def test_indexes_exist(conn):
    names = {
        r[0] for r in conn.execute("SELECT indexname FROM pg_indexes WHERE schemaname='public'")
    }
    assert {"entries_live_name", "pins_live", "events_entry", "versions_retired"} <= names


def test_no_column_holds_a_value_hash_or_length(conn):
    cols = [
        (r[0], r[1])
        for r in conn.execute(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = 'public'"
        )
    ]
    assert cols
    for table, column in cols:
        for banned in ("value", "hash", "length", "size", "bytes"):
            assert banned not in column, (table, column)
