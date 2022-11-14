# from flask import current_app
from project.user.main import main_bp

@main_bp.route('/')
@main_bp.route('/index')
def index():
    return "Hello World"