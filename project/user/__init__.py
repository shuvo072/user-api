#from flask_mail import Mail
from flask import Flask,jsonify
from flask_bcrypt import Bcrypt
#from flask_restx import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from project.user.config import Config

app = Flask(__name__)
#api = Api(app)
app.config.from_object(Config)

#mail = Mail(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
migrate = Migrate(app,db)

from project.user.api.views import user_api_blueprint,auth_blueprint,verified_user_blueprint
app.register_blueprint(verified_user_blueprint)
app.register_blueprint(auth_blueprint)
app.register_blueprint(user_api_blueprint)



from project.user import routes,models