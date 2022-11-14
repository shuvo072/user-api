from project.user import create_app,db
from project.user.models import User
app=create_app()

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}