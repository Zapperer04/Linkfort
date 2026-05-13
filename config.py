import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY')
    JWT_SECRET_KEY = SECRET_KEY or 'dev-secret-key-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = 86400  # 24 hours
    
    # URLs
    BASE_URL = os.getenv('BASE_URL', 'http://localhost:5000')
    SHORT_URL_BASE = os.getenv('SHORT_URL_BASE', os.getenv('BASE_URL', 'http://localhost:5000'))
    API_BASE_URL = os.getenv('API_BASE_URL', os.getenv('BASE_URL', 'http://localhost:5000'))
    FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:3000')
    
    # Environment
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = FLASK_ENV == 'development'
    
    # APIs
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    
    # Redis
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')