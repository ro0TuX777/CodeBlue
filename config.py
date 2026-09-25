"""
Configuration settings for the CodeBlue application.
This file contains environment-specific settings that can be modified for deployment.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

class Config:
    """Base configuration class."""
    # Flask settings
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'default-secret-key-for-development')
    DEBUG = False
    TESTING = False
    
    # Server settings
    HOST = os.environ.get('CODEBLUE_HOST', '0.0.0.0')
    PORT = int(os.environ.get('CODEBLUE_PORT', 5001))
    
    # Database settings
    # Relative sqlite URI is resolved by Flask-SQLAlchemy against instance/,
    # i.e. this is instance/bluescrub_database.db.
    SQLALCHEMY_DATABASE_URI = 'sqlite:///bluescrub_database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # GitHub API settings
    GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
    
    # Application paths
    UNTESTED_DIR = 'Untested'
    SAVED_REPOS_DIR = 'saved_repositories'
    
    # Logging settings
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    
class ProductionConfig(Config):
    """Production configuration."""
    # In production, ensure a proper secret key is set
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
    
    # Set more restrictive file permissions in production
    @classmethod
    def init_app(cls, app):
        """Initialize production-specific settings."""
        # Set secure cookies
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        
        # Set logging to file in production
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not os.path.exists('logs'):
            os.mkdir('logs')
            
        file_handler = RotatingFileHandler(
            'logs/codeblue.log',
            maxBytes=10485760,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('CodeBlue startup')

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

# Get the active configuration
def get_config():
    """Return the appropriate configuration object based on environment."""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])
