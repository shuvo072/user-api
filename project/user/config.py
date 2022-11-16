import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))
postgres_docker_base = 'postgresql://postgres:shuvo72@localhost:5555/'
database_name = 'users'

#* Divide config into classes eg: Staging, Production *#

class BaseConfig:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'verysecretkey'
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_URL = 'redis://localhost:6379/0'
    SQLALCHEMY_ECHO=True


class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_DATABASE_URI = postgres_docker_base + database_name


class TestingConfig(BaseConfig):
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    BCRYPT_LOG_ROUNDS = 13
    SQLALCHEMY_DATABASE_URI = postgres_docker_base + database_name + '_test'
    PRESERVE_CONTEXT_ON_EXCEPTION = False


class ProductionConfig(BaseConfig):
    """Production configuration."""
    SECRET_KEY = 'verysecretkey'
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'postgresql:///example'

# class Config(object):
#     SECRET_KEY = os.environ.get('SECRET_KEY') or 'verysecretkey'
#     SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
#         'postgresql://postgres:shuvo72@localhost:5555/users'
#     BCRYPT_LOG_ROUNDS = 13
#     SQLALCHEMY_TRACK_MODIFICATIONS = False