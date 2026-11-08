import uuid

import psycopg
import pytest
from agents_common.db.migrate import run_migrations

PACKAGE = "agents_vault"


def add_entry(conn, name="Database password", **cols) -> uuid.UUID:
    values = {"name": name, "description": "d", **cols}
    names = ", ".join(values)
    marks = ", ".join(["%s"] * len(values))
    return conn.execute(
        f"INSERT INTO entries ({names}) VALUES ({marks}) RETURNING id", tuple(values.values())
    ).fetchone()[0]


def test_applies_twice_idempotent(empty_db_url):
    assert run_migrations(empty_db_url, PACKAGE) == ["0001_vault.sql", "0002_entry_envs.sql"]
    assert run_migrations(empty_db_url, PACKAGE) == []
    with psycopg.connect(empty_db_url) as conn:
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            )
        }
    assert {"entries", "entry_envs", "versions", "pins", "events"} <= tables


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


def test_live_name_is_unique_case_insensitively_until_deleted(conn):
    first = add_entry(conn)
    with pytest.raises(psycopg.errors.UniqueViolation):
        add_entry(conn)
    with pytest.raises(psycopg.errors.UniqueViolation):
        add_entry(conn, name="DATABASE PASSWORD")
    conn.execute("UPDATE entries SET deleted_at = now() WHERE id = %s", (first,))
    add_entry(conn)


@pytest.mark.parametrize("name", ["", " lead", "trail ", "A" * 121])
def test_entry_name_check(conn, name):
    with pytest.raises(psycopg.errors.CheckViolation):
        add_entry(conn, name=name)


def test_entry_name_check_accepts_free_text(conn):
    add_entry(conn, name="Harbor admin credentials")
    add_entry(conn, name="a-b_c.d")
    add_entry(conn, name="A" * 120)


def add_env(conn, entry, env="API_KEY", position=0, protected=True, value=None):
    conn.execute(
        "INSERT INTO entry_envs (entry_id, env, position, protected, value)"
        " VALUES (%s, %s, %s, %s, %s)",
        (entry, env, position, protected, value),
    )


def test_entry_env_value_check(conn):
    entry = add_entry(conn)
    add_env(conn, entry, "SECRET", 0, True, None)
    add_env(conn, entry, "URL", 1, False, "https://x")
    add_env(conn, entry, "EMPTY", 2, False, "")
    add_env(conn, entry, "BIG", 3, False, "x" * 4096)
    for env, protected, value in [
        ("P_WITH_VALUE", True, "v"),
        ("R_WITHOUT_VALUE", False, None),
        ("R_TOO_BIG", False, "\u00e9" * 2049),
    ]:
        with pytest.raises(psycopg.errors.CheckViolation):
            add_env(conn, entry, env, 10, protected, value)


@pytest.mark.parametrize("env", ["lower", "1A", "A-B", "", "A" * 129])
def test_entry_env_name_check(conn, env):
    entry = add_entry(conn)
    with pytest.raises(psycopg.errors.CheckViolation):
        add_env(conn, entry, env)


def test_entry_env_unique_within_an_entry_but_not_across(conn):
    one = add_entry(conn, name="one")
    two = add_entry(conn, name="two")
    add_env(conn, one, "GITHUB_TOKEN", 0)
    add_env(conn, two, "GITHUB_TOKEN", 0)
    with pytest.raises(psycopg.errors.UniqueViolation):
        add_env(conn, one, "GITHUB_TOKEN", 1)
    with pytest.raises(psycopg.errors.UniqueViolation):
        add_env(conn, one, "OTHER", 0)


def test_pins_carry_the_entry_env(conn):
    entry = add_entry(conn)
    with pytest.raises(psycopg.errors.NotNullViolation):
        conn.execute(
            "INSERT INTO pins (session_id, env, entry_id, version) VALUES (%s, 'A', %s, 1)",
            (uuid.uuid4(), entry),
        )


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


# The one value column: a readable env's value, never a protected one (a CHECK makes a protected
# row's value NULL, see test_entry_env_value_check).
READABLE_VALUE_COLUMN = ("entry_envs", "value")


def test_no_column_holds_a_value_hash_or_length(conn):
    cols = [
        (r[0], r[1])
        for r in conn.execute(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = 'public'"
        )
    ]
    assert cols
    assert READABLE_VALUE_COLUMN in cols
    for table, column in cols:
        if (table, column) == READABLE_VALUE_COLUMN:
            continue
        for banned in ("value", "hash", "length", "size", "bytes"):
            assert banned not in column, (table, column)
