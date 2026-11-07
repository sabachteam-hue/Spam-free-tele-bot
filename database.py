import sqlite3
import json
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "telecampaign.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS proxies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        proxy_type TEXT NOT NULL DEFAULT 'socks5',
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        username TEXT DEFAULT '',
        password TEXT DEFAULT '',
        status TEXT DEFAULT 'untested',
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT DEFAULT '',
        api_id INTEGER NOT NULL DEFAULT 2040,
        api_hash TEXT NOT NULL DEFAULT 'b18441a1ff607e10a989891a5462e627',
        session_string TEXT DEFAULT '',
        proxy_id INTEGER DEFAULT NULL,
        status TEXT DEFAULT 'disconnected',
        username TEXT DEFAULT '',
        telegram_user_id TEXT DEFAULT '',
        daily_quota INTEGER DEFAULT 1500,
        sent_today INTEGER DEFAULT 0,
        quota_date TEXT DEFAULT '',
        cooldown_until TEXT DEFAULT NULL,
        last_sync_at TEXT DEFAULT NULL,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS destinations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER NOT NULL,
        telegram_id INTEGER NOT NULL,
        topic_id INTEGER DEFAULT NULL,
        title TEXT NOT NULL,
        parent_title TEXT DEFAULT NULL,
        username TEXT DEFAULT '',
        kind TEXT DEFAULT 'group',
        can_post INTEGER DEFAULT 1,
        restriction_until TEXT DEFAULT NULL,
        slowmode_seconds INTEGER DEFAULT 0,
        participants_count INTEGER DEFAULT 0,
        auto_tags TEXT DEFAULT '["standard"]',
        category TEXT DEFAULT 'standard',
        allow_forwards INTEGER DEFAULT 1,
        allow_links INTEGER DEFAULT 1,
        allow_media INTEGER DEFAULT 1,
        rules_summary TEXT DEFAULT '',
        last_sent_at TEXT DEFAULT NULL,
        updated_at TEXT,
        UNIQUE(account_id, telegram_id, topic_id)
    )
    """)

    # Auto-migrate existing destinations table if needed
    existing_cols = [r[1] for r in cur.execute("PRAGMA table_info(destinations)").fetchall()]
    migrations = {
        "auto_tags": "TEXT DEFAULT '[\"standard\"]'",
        "category": "TEXT DEFAULT 'standard'",
        "allow_forwards": "INTEGER DEFAULT 1",
        "allow_links": "INTEGER DEFAULT 1",
        "allow_media": "INTEGER DEFAULT 1",
        "rules_summary": "TEXT DEFAULT ''",
        "last_sent_at": "TEXT DEFAULT NULL",
    }
    for col, col_def in migrations.items():
        if col not in existing_cols:
            cur.execute(f"ALTER TABLE destinations ADD COLUMN {col} {col_def}")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        mode TEXT NOT NULL DEFAULT 'text',
        content TEXT DEFAULT '',
        parse_mode TEXT DEFAULT 'html',
        source_account_id INTEGER DEFAULT NULL,
        source_message_id INTEGER DEFAULT NULL,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS campaigns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        account_id INTEGER NOT NULL,
        template_id INTEGER NOT NULL,
        destination_ids TEXT NOT NULL DEFAULT '[]',
        repeat_count INTEGER NOT NULL DEFAULT 300,
        current_round INTEGER NOT NULL DEFAULT 0,
        round_delay_min_seconds INTEGER NOT NULL DEFAULT 15,
        round_delay_max_seconds INTEGER NOT NULL DEFAULT 45,
        group_interval_seconds INTEGER NOT NULL DEFAULT 60,
        simulate_typing INTEGER NOT NULL DEFAULT 1,
        scheduled_at TEXT DEFAULT NULL,
        next_run_at TEXT DEFAULT NULL,
        status TEXT NOT NULL DEFAULT 'running',
        total_sent INTEGER NOT NULL DEFAULT 0,
        total_failed INTEGER NOT NULL DEFAULT 0,
        last_error TEXT DEFAULT NULL,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS delivery_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_id INTEGER,
        account_id INTEGER,
        destination_id INTEGER,
        destination_title TEXT,
        round_number INTEGER,
        status TEXT NOT NULL,
        reason TEXT DEFAULT '',
        message_id INTEGER DEFAULT NULL,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()
