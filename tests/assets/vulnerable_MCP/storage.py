import sqlite3

DATABASE_PATH = "/tmp/vulnerable_mcp.db"  # AUTH002


def init_storage() -> None:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("create table if not exists events (id integer primary key, payload text)")
    conn.commit()
    conn.close()


def append_event(payload: str) -> None:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("insert into events (payload) values (?)", (payload,))
    conn.commit()
    conn.close()


def fetch_events() -> list[str]:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.execute("select payload from events")
    rows = [row[0] for row in cursor.fetchall()]
    conn.close()
    return rows
