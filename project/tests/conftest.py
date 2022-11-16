import pytest,datetime,jwt,os
from project.user import create_app,db
from project.user.config import TestingConfig




@pytest.fixture(scope='module')
def test_app():
    app=create_app()
    app.config.from_object('project.user.config.TestingConfig')
    with app.app_context():
        yield app


@pytest.fixture(scope='module')
def test_database():
    app=create_app(config_class=TestingConfig)
    with app.app_context(): 
        db.create_all()
        yield db
        db.session.remove()
        db.drop_all()


@pytest.fixture(scope='module')
def test_token_generate():
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600),
        'iat': datetime.datetime.utcnow(),
        'sub': '2'
    }
    token = jwt.encode(payload,'verysecretkey',algorithm='HS256')
    yield token

