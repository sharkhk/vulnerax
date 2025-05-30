from datetime import timedelta
import os

class Config:
    ENV = os.getenv("FLASK_ENV", "production")
    DEBUG = ENV == "development"
    TESTING = False
    CIRCL_API_URL = "https://cve.circl.lu/api"
    CACHE_TYPE = "SimpleCache"
    CACHE_DEFAULT_TIMEOUT = 300
    REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")

class DevelopmentConfig(Config):
    DEBUG = True
    CACHE_DEFAULT_TIMEOUT = 60

class ProductionConfig(Config):
    pass
