from flask import Flask
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from project.user.config import DevelopmentConfig
from flask_caching import Cache

#* Application Factory Pattern needs to be implemented *#

cors = CORS()
bcrypt = Bcrypt()
db = SQLAlchemy()
migrate = Migrate()
cache=Cache()

def create_app(config_class=DevelopmentConfig):
    app = Flask(__name__)
    app.config.from_object(config_class)

    bcrypt.init_app(app)
    db.init_app(app)
    migrate.init_app(app,db)
    cache.init_app(app)

    from project.user.api import user_api_blueprint,auth_blueprint,verified_user_blueprint,job_blueprint,job_history_blueprint
    app.register_blueprint(job_history_blueprint)
    app.register_blueprint(job_blueprint)
    app.register_blueprint(verified_user_blueprint)
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(user_api_blueprint)

    from project.user.main import main_bp
    app.register_blueprint(main_bp)
    
    return app
        
#* Is this line needed? *#
