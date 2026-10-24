"""
AI-Powered Autonomous SOC Assistant - Configuration & Settings
Defines file paths, model configurations, risk scoring parameters,
MITRE ATT&CK reference data, and runtime options.
"""

from pathlib import Path
import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # Graceful manual fallback parser for .env if python-dotenv is not installed in current environment
    _env_file = Path(__file__).resolve().parent.parent / ".env"
    if _env_file.exists():
        with open(_env_file, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    os.environ.setdefault(_k.strip(), _v.strip())

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
SAMPLE_DATA_DIR = DATA_DIR / "sample"
MODELS_DIR = BASE_DIR / "models"
KNOWLEDGE_BASE_DIR = BASE_DIR / "knowledge_base"
KB_DOCS_DIR = KNOWLEDGE_BASE_DIR / "documents"
KB_INDEX_DIR = KNOWLEDGE_BASE_DIR / "faiss_index"
ASSETS_DIR = BASE_DIR / "assets"

# Ensure runtime directories exist
for path in [DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, SAMPLE_DATA_DIR,
             MODELS_DIR, KNOWLEDGE_BASE_DIR, KB_DOCS_DIR, KB_INDEX_DIR, ASSETS_DIR]:
    path.mkdir(parents=True, exist_ok=True)

# Database Configuration
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", DATA_DIR / "soc_database.sqlite"))

# Machine Learning Model Configuration
MODEL_FILE = MODELS_DIR / "soc_rf_pipeline.joblib"
METADATA_FILE = MODELS_DIR / "model_metadata.json"
MODEL_VERSION = "1.0.0"

# Target Attack Categories Supported (CIC-IDS2017 multi-class mapping)
LABEL_MAPPING = {
    "BENIGN": "Benign",
    "BOT": "Botnet",
    "FTP-PATATOR": "Brute Force (FTP)",
    "SSH-PATATOR": "Brute Force (SSH)",
    "DDOS": "DDoS",
    "DOS HULK": "DoS (Hulk)",
    "DOS GOLDENEYE": "DoS (GoldenEye)",
    "DOS SLOWLORIS": "DoS (Slowloris)",
    "DOS SLOWHTTPTEST": "DoS (SlowHTTPTest)",
    "HEARTBLEED": "Vulnerability Exploit (Heartbleed)",
    "INFILTRATION": "Infiltration",
    "PORTSCAN": "Port Scan",
    "WEB ATTACK - BRUTE FORCE": "Web Attack (Brute Force)",
    "WEB ATTACK - XSS": "Web Attack (XSS)",
    "WEB ATTACK - SQL INJECTION": "Web Attack (SQL Injection)",
}

# LLM Configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-flash-latest")

# Risk Scoring Weight Configuration (Total = 100)
# Base severity contribution for attack classes
BASE_SEVERITY_SCORES = {
    "Benign": 0,
    "Port Scan": 35,
    "Brute Force (FTP)": 55,
    "Brute Force (SSH)": 65,
    "DoS (SlowHTTPTest)": 65,
    "DoS (Slowloris)": 70,
    "DoS (GoldenEye)": 75,
    "DoS (Hulk)": 80,
    "DDoS": 85,
    "Web Attack (Brute Force)": 65,
    "Web Attack (XSS)": 70,
    "Web Attack (SQL Injection)": 90,
    "Botnet": 85,
    "Vulnerability Exploit (Heartbleed)": 95,
    "Infiltration": 95,
}

# Upload Processing Limits
MAX_UPLOAD_SIZE_MB = 100
MAX_BATCH_PREDICTION_ROWS = 50000
DEFAULT_PREVIEW_ROWS = 100
