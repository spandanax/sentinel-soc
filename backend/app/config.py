import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# Database path (defaults to SQLite in backend/data/sentinel.db)
DB_PATH = os.getenv("SENTINEL_DB_PATH", str(DATA_DIR / "sentinel.db"))

# Brute Force Detection defaults
DEFAULT_WINDOW_MINUTES = int(os.getenv("BRUTE_FORCE_WINDOW_MINUTES", "10"))
DEFAULT_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))

# Allowed CORS origins for frontend
CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
