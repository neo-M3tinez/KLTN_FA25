"""
Configuration for Security Agent Planner System
"""

import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).parent
RESULTS_DIR = BASE_DIR / "agent_results"
LOGS_DIR = BASE_DIR / "logs"

# Create directories
RESULTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# Webhook settings
WEBHOOK_HOST = os.getenv("WEBHOOK_HOST", "0.0.0.0")
WEBHOOK_PORT = int(os.getenv("WEBHOOK_PORT", "5000"))

# LLM settings (optional - for advanced features)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.0"))

# Agent settings
MAX_AGENT_ITERATIONS = int(os.getenv("MAX_AGENT_ITERATIONS", "10"))
AGENT_TIMEOUT = int(os.getenv("AGENT_TIMEOUT", "300"))  # 5 minutes

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = LOGS_DIR / "agent_system.log"

# Security
API_KEY = os.getenv("API_KEY", "")  # Optional API key for webhook auth
ALLOWED_IPS = os.getenv("ALLOWED_IPS", "").split(",") if os.getenv("ALLOWED_IPS") else []

# Playbook settings
ENABLE_AUTO_RESPONSE = os.getenv("ENABLE_AUTO_RESPONSE", "true").lower() == "true"
CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.3"))

# Result retention
MAX_RESULTS = int(os.getenv("MAX_RESULTS", "1000"))  # Max results to keep
RESULT_RETENTION_DAYS = int(os.getenv("RESULT_RETENTION_DAYS", "30"))
