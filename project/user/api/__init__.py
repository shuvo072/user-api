from flask import Blueprint

user_api_blueprint = Blueprint('user-api', __name__)
auth_blueprint = Blueprint('auth', __name__)
verified_user_blueprint = Blueprint('verified-user-api',__name__)
job_blueprint = Blueprint('job-api',__name__)
job_history_blueprint = Blueprint('job-history-api',__name__)

from project.user.api import views