import os,logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from project.user.config import DevelopmentConfig
from flask_caching import Cache

#* Application Factory Pattern needs to be implemented *#

bcrypt = Bcrypt()
db = SQLAlchemy()
migrate = Migrate()
cache=Cache()

def create_app(config_class=DevelopmentConfig):
    app = Flask(__name__)
    app_settings = os.getenv(
        'APP_SETTINGS',
        'project.user.config.DevelopmentConfig'
    )
    app.config.from_object(app_settings)

    bcrypt.init_app(app)
    db.init_app(app)
    migrate.init_app(app,db)
    cache.init_app(app)

    from project.user.api import user_api_blueprint,auth_blueprint,verified_user_blueprint
    app.register_blueprint(verified_user_blueprint)
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(user_api_blueprint)

    from project.user.main import main_bp
    app.register_blueprint(main_bp)

    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/user-api.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

        app.logger.setLevel(logging.INFO)
        app.logger.info('User API startup')
    
    return app
        
#* Is this line needed? *#
