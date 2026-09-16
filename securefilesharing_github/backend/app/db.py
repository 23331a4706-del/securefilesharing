import os
import pymysql
import pymysql.cursors
import sqlite3
from app.config import Config

class SQLiteDictCursor:
    """Wrapper to make SQLite fetch rows as dictionaries like PyMySQL DictCursor."""
    def __init__(self, cursor):
        self.cursor = cursor
        self.lastrowid = cursor.lastrowid

    @property
    def rowcount(self):
        return self.cursor.rowcount

    def execute(self, sql, params=()):
        # Convert %s placeholder to ? for SQLite
        sqlite_sql = sql.replace('%s', '?')
        res = self.cursor.execute(sqlite_sql, params)
        self.lastrowid = self.cursor.lastrowid
        return res

    def fetchone(self):
        row = self.cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    def fetchall(self):
        rows = self.cursor.fetchall()
        return [dict(r) for r in rows]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class SQLiteConnectionWrapper:
    """Wrapper around sqlite3 connection to mirror PyMySQL interface with autocommit."""
    def __init__(self, conn):
        self.conn = conn
        self.conn.isolation_level = None  # Autocommit mode
        self.conn.row_factory = sqlite3.Row

    def cursor(self):
        return SQLiteDictCursor(self.conn.cursor())

    def close(self):
        try:
            self.conn.commit()
        except Exception:
            pass
        self.conn.close()


def get_db_connection():
    """
    Establishes and returns a database connection.
    Defaults to PyMySQL (MySQL). Automatically falls back to zero-setup SQLite database
    if USE_SQLITE is true or if MySQL is offline.
    """
    use_sqlite_env = os.getenv("USE_SQLITE", "true").lower() == "true"
    
    if use_sqlite_env:
        return _get_sqlite_connection()

    try:
        connection = pymysql.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )
        return connection
    except Exception:
        # Fallback to SQLite if MySQL fails
        return _get_sqlite_connection()


def _get_sqlite_connection():
    db_path = os.getenv("SQLITE_DB_PATH", "secure_file_sharing.db")
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.isolation_level = None  # Autocommit mode
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) NOT NULL UNIQUE,
            email VARCHAR(100) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            wallet_address VARCHAR(100) DEFAULT NULL,
            ecc_public_key TEXT DEFAULT NULL,
            ecc_private_key_encrypted TEXT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            original_filename VARCHAR(255) NOT NULL,
            stored_filename VARCHAR(255) NOT NULL UNIQUE,
            file_size BIGINT NOT NULL,
            mime_type VARCHAR(100) DEFAULT 'application/octet-stream',
            encryption_algorithm VARCHAR(50) DEFAULT 'AES-256-GCM',
            nonce VARCHAR(255) NOT NULL,
            encrypted_key TEXT NOT NULL,
            storage_path VARCHAR(255) NOT NULL,
            sha256_hash CHAR(64) DEFAULT NULL,
            ipfs_cid VARCHAR(100) DEFAULT NULL,
            blockchain_recorded BOOLEAN DEFAULT 0,
            blockchain_tx_hash VARCHAR(100) DEFAULT NULL,
            status VARCHAR(50) DEFAULT 'encrypted',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS file_key_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            sender_ephemeral_public_key TEXT NOT NULL,
            encrypted_aes_key TEXT NOT NULL,
            key_wrap_nonce VARCHAR(255) NOT NULL,
            active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id),
            UNIQUE (file_id, receiver_id)
        );
    """)
    return SQLiteConnectionWrapper(conn)
