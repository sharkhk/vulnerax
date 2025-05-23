from datetime import timedelta
import os

class Config:
    ENV = os.getenv("FLASK_ENV", "production")
    DEBUG = ENV == "development"
    TESTING = False
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    NVD_API_KEY = "7fbc28b6-88f1-4c43-adbd-a6428ed31135"
    CACHE_TYPE = "SimpleCache"
    CACHE_DEFAULT_TIMEOUT = 300  # seconds
    REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")
    # Celery configuration
    CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
    # Notification settings
    SMTP_SERVER = os.getenv("SMTP_SERVER")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

class DevelopmentConfig(Config):
    DEBUG = True
    CACHE_DEFAULT_TIMEOUT = 60

class ProductionConfig(Config):
    pass
