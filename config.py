from datetime import timedelta
import os

class Config:
    ENV = os.getenv("FLASK_ENV", "production")
    DEBUG = ENV == "development"
    TESTING = False
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    NVD_API_KEY = os.getenv("NVD_API_KEY")
    CACHE_TYPE = "SimpleCache"
    CACHE_DEFAULT_TIMEOUT = 300  # seconds
    REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")
