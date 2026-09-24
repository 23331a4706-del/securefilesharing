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

    def commit(self):
        try:
            self.conn.commit()
        except Exception:
            pass

    def close(self):
        try:
            self.conn.commit()
        except Exception:
            pass
        self.conn.close()


def get_db_connection():
    """
    Establishes and returns a database connection.
    Supports cloud MySQL/Postgres via DATABASE_URL or PyMySQL.
    Automatically falls back to persistent SQLite database with WAL mode.
    """
    db_url = os.getenv("DATABASE_URL") or os.getenv("MYSQL_URL") or os.getenv("CLEARDB_DATABASE_URL") or os.getenv("JAWSDB_URL")
    use_sqlite_env = os.getenv("USE_SQLITE", "true").lower() == "true"
    
    if db_url:
        try:
            import urllib.parse
            url = urllib.parse.urlparse(db_url)
            ssl_config = None
            if "ssl" in db_url.lower() or os.getenv("MYSQL_SSL", "false").lower() == "true":
                ssl_config = {"ssl": {}}
            
            connection = pymysql.connect(
                host=url.hostname,
                port=url.port or 3306,
                user=url.username,
                password=url.password,
                database=url.path.lstrip('/'),
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True,
                ssl=ssl_config
            )
            _init_mysql_tables(connection)
            return connection
        except Exception as e:
            print("Remote DATABASE_URL connection error:", e)

    if not use_sqlite_env:
        try:
            ssl_config = None
            if os.getenv("MYSQL_SSL", "false").lower() == "true":
                ssl_config = {"ssl": {}}

            connection = pymysql.connect(
                host=Config.DB_HOST,
                port=Config.DB_PORT,
                user=Config.DB_USER,
                password=Config.DB_PASSWORD,
                database=Config.DB_NAME,
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True,
                ssl=ssl_config
            )
            _init_mysql_tables(connection)
            return connection
        except Exception:
            pass

    return _get_sqlite_connection()


def _init_mysql_tables(conn):
    """Auto-creates MySQL tables if missing when connecting to cloud or local MySQL."""
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    email VARCHAR(100) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    wallet_address VARCHAR(100) DEFAULT NULL,
                    ecc_public_key TEXT DEFAULT NULL,
                    ecc_private_key_encrypted TEXT DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    owner_id INT NOT NULL,
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
                    blockchain_recorded TINYINT(1) DEFAULT 0,
                    blockchain_tx_hash VARCHAR(100) DEFAULT NULL,
                    status VARCHAR(50) DEFAULT 'encrypted',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_key_shares (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    file_id INT NOT NULL,
                    sender_id INT NOT NULL,
                    receiver_id INT NOT NULL,
                    sender_ephemeral_public_key TEXT NOT NULL,
                    encrypted_aes_key TEXT NOT NULL,
                    key_wrap_nonce VARCHAR(255) NOT NULL,
                    active TINYINT(1) DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                    FOREIGN KEY (sender_id) REFERENCES users(id),
                    FOREIGN KEY (receiver_id) REFERENCES users(id),
                    UNIQUE KEY unique_file_receiver (file_id, receiver_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
    except Exception as e:
        print("MySQL table init notice:", e)


def _get_sqlite_connection():
    default_db = os.path.abspath(os.path.join(Config.BASE_DIR, "..", "secure_file_sharing.db"))
    db_path = os.getenv("SQLITE_DB_PATH", default_db)
    
    dir_path = os.path.dirname(os.path.abspath(db_path))
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
        
    conn = sqlite3.connect(db_path, timeout=15.0)
    conn.isolation_level = None  # Autocommit mode
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
    except Exception:
        pass

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
