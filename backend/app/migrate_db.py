import sqlite3
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Absolute path for DB
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# app is in backend/app, data is in root data/
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
    ("fusion_trace", "TEXT")
]

def migrate():
    if not os.path.exists(DB_PATH):
        logger.error(f"Database not found at {DB_PATH}. Run the app first to initialize DB.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get existing columns
    cursor.execute("PRAGMA table_info(scans)")
    existing_columns = [row[1] for row in cursor.fetchall()]

    added_count = 0
    for col_name, col_type in NEW_COLUMNS:
        if col_name not in existing_columns:
            logger.info(f"Adding column '{col_name}' to 'scans' table...")
            try:
                cursor.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}")
                added_count += 1
            except Exception as e:
                logger.error(f"Failed to add column {col_name}: {e}")
        else:
            logger.info(f"Column '{col_name}' already exists.")

    conn.commit()
    conn.close()
    logger.info(f"Migration complete. Added {added_count} new columns.")

if __name__ == "__main__":
    migrate()
