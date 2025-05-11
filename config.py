import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///policy_app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # CSRF Protection settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.getenv('CSRF_SECRET_KEY', SECRET_KEY)
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour in seconds
    
    # Mail settings
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_USERNAME')
    MAIL_DEBUG = True  # Enable debug mode for troubleshooting
    
    # Security settings
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPER = True
    PASSWORD_REQUIRE_LOWER = True
    PASSWORD_REQUIRE_NUMBERS = True
    PASSWORD_REQUIRE_SPECIAL = True
    
    # Login attempt settings
    MAX_LOGIN_ATTEMPTS = 3
    LOGIN_ATTEMPT_TIMEOUT = 300  # 5 minutes in seconds
    
    # OTP settings
    OTP_VALIDITY = 300  # 5 minutes in seconds
    OTP_LENGTH = 6
    
    # IP restriction settings
    ALLOWED_IPS = []  # Empty list means no IP restrictions
    
    # Time-based access settings
    WORKING_HOURS_START = 9  # 9 AM
    WORKING_HOURS_END = 23   # 5 PM
    WORKING_DAYS = [0, 1, 2, 3, 4]  # Monday to Friday (0 = Monday) 