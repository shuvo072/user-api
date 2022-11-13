from project.user import app

@app.route('/')
@app.route('/index')
def index():
    return "Hello World"