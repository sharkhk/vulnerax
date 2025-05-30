from datetime import timedelta
import os

class Config:
    ENV = os.getenv("FLASK_ENV", "production")
    DEBUG = ENV == "development"
    TESTING = False
    # NVD API and CIRCL feed URLs
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    CIRCL_API_URL = "https://cve.circl.lu/api"
    NVD_API_KEY = os.getenv("NVD_API_KEY", "7fbc28b6-88f1-4c43-adbd-a6428ed31135")
    CACHE_TYPE = "SimpleCache"
    CACHE_DEFAULT_TIMEOUT = 300  # seconds
    REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")

class DevelopmentConfig(Config):
    DEBUG = True
    CACHE_DEFAULT_TIMEOUT = 60

class ProductionConfig(Config):
    pass
