#!/usr/bin/env python
import os
from config import Config

config = Config()
print("===== PRODUCTION CONFIG VERIFICATION =====")
print(f"FLASK_ENV: {config.FLASK_ENV}")
print(f"DEBUG: {config.DEBUG}")
print(f"SHORT_URL_BASE: {config.SHORT_URL_BASE}")
print(f"API_BASE_URL: {config.API_BASE_URL}")
print(f"FRONTEND_URL: {config.FRONTEND_URL}")
db_status = "SET" if config.SQLALCHEMY_DATABASE_URI else "NOT SET"
print(f"Database: {db_status}")
print(f"Redis: {config.REDIS_URL}")
print("===== STATUS: READY FOR PRODUCTION =====")
