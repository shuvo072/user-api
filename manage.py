from project.user import create_app,db
from project.user.models import User
app=create_app()

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}

# from flask.cli import FlaskGroup
# from project.user import app

# cli = FlaskGroup (app)


# if __name__=='__main__':
#     cli()