import sqlite3
from typing import Generator
from contextlib import contextmanager
from app.config import DB_PATH

def init_db(db_path: str = DB_PATH) -> None:
    """Initialize database tables and indexes."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    cursor = conn.cursor()

    # Events table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT,
        username TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """)

    # Alerts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        target_username TEXT,
        reason TEXT NOT NULL,
        event_count INTEGER NOT NULL,
        first_event_time TEXT NOT NULL,
        last_event_time TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'New',
        notes TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """)

    # Indexes for fast querying
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(username);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);")

    conn.commit()
    conn.close()

def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Create a connection with sqlite3.Row factory for dictionary-like access."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def get_db(db_path: str = DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for DB sessions."""
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
