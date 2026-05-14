import sqlite3
import os
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Absolute path for DB
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "data", "linkveil.db"))

NEW_COLUMNS = [
    ("screenshot_path", "STRING"),
    ("visual_score", "FLOAT"),
    ("brand_logo_guess", "STRING"),
    ("probe_artifacts", "TEXT"),
    ("domain_age_days", "INTEGER"),
    ("registrar", "STRING"),
    ("whois_privacy", "BOOLEAN"),
    ("threat_intel_match", "BOOLEAN DEFAULT 0"),
    ("threat_intel_source", "STRING"),
    ("fusion_trace", "TEXT"),
    ("tld", "STRING"),
    ("functional_category", "STRING"),
    ("client_id", "STRING")
]

def is_safe_sql_identifier(name):
    """Validate SQL column names."""
    return re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name) is not None

def is_safe_sql_type(t):
    """Validate SQL column types."""
    pattern = r'^(TEXT|INTEGER|REAL|BLOB|NUMERIC|STRING|BOOLEAN|FLOAT)(\s+DEFAULT\s+0)?$'
    return re.match(pattern, t, re.IGNORECASE) is not None



def add_missing_columns(cursor, logger, table_name, columns):
    """
    Helper function to add missing columns to a table.
    Ensures table exists and validates identifiers before altering.
    """
    if not is_safe_sql_identifier(table_name):
        logger.error(f"Insecure table name: {table_name}")
        return 0
        
    added_count = 0
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    if not cursor.fetchone():
        logger.warning(f"Table '{table_name}' not found.")
        return 0
        
    cursor.execute(f"PRAGMA table_info({table_name})")
    existing_cols = [row[1] for row in cursor.fetchall()]

    for col_name, col_type in columns:
        if col_name not in existing_cols:
            if not is_safe_sql_identifier(col_name) or not is_safe_sql_type(col_type):
                logger.error(f"Insecure identifier or type for {table_name}: {col_name} {col_type}")
                continue
            
            logger.info(f"Adding column '{col_name}' to '{table_name}' table...")
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
            added_count += 1
            
    return added_count

def migrate(db_path=None):
    """
    Probes for the database file in known locations and applies schema updates.
    Uses DB_PATH as the default if no explicit path is provided.
    """
    if db_path is None:
        db_path = DB_PATH
        
    # Probing logic: check multiple potential locations relative to the backend root
    POSSIBLE_PATHS = [
        db_path,
        os.path.abspath(os.path.join(BASE_DIR, "..", "linkveil.db")),
        os.path.abspath(os.path.join(BASE_DIR, "..", "..", "backend", "linkveil.db"))
    ]
    
    # If the current db_path doesn't exist, try the alternatives
    if not os.path.exists(db_path):
        for p in POSSIBLE_PATHS:
            if os.path.exists(p):
                db_path = p
                break

    if not os.path.exists(db_path):
        logger.error(f"Database not found. Checked: {POSSIBLE_PATHS}")
        return

    logger.info(f"Using database at {db_path}")
    
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Update tables using refactored helper
        added_scans = add_missing_columns(cursor, logger, 'scans', NEW_COLUMNS)
        
        email_cols = [("client_id", "STRING")]
        added_emails = add_missing_columns(cursor, logger, 'email_scans', email_cols)

        # Create forensic_sessions table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS forensic_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT UNIQUE NOT NULL,
                tenant_id TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        session_cols = [("is_admin", "BOOLEAN DEFAULT 0")]
        added_sessions = add_missing_columns(cursor, logger, 'forensic_sessions', session_cols)

        conn.commit()
        logger.info(f"Migration complete. Scans: +{added_scans}, Emails: +{added_emails}, Sessions: +{added_sessions}")

    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Migration failed: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    migrate()
