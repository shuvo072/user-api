import pytest,datetime,jwt
from project.user import create_app,db
from project.user.models import User
from project.user.config import TestingConfig




@pytest.fixture(scope='module')
def test_app():
    app=create_app(TestingConfig)
    with app.app_context():
        yield app


@pytest.fixture(scope='module')
def test_admin_database():
    app=create_app(TestingConfig)
    with app.app_context(): 
        db.create_all()
        user = User(
                    user_firstname="Mehadi Hasan",
                    user_lastname="Shuvo",
                    user_username="shuvo72",
                    password="admin",
                    admin=1
                )
        db.session.add(user)
        db.session.commit()
        yield db
        db.session.remove()
        db.drop_all()


# @pytest.fixture(scope='module')
# def test_database():
#     app=create_app(TestingConfig)
#     with app.app_context(): 
#         db.create_all()
#         yield db
#         db.session.remove()
#         db.drop_all()


@pytest.fixture(scope='module')
def test_token_generate():
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600),
        'iat': datetime.datetime.utcnow(),
        'sub': 1
    }
    token = jwt.encode(payload,'verysecretkey',algorithm='HS256')
    yield token

# @pytest.fixture(scope='module')
# def test_user_token_generate():
#     payload = {
#         'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600),
#         'iat': datetime.datetime.utcnow(),
#         'sub': 1
#     }
#     token = jwt.encode(payload,'verysecretkey',algorithm='HS256')
#     yield token

# @pytest.fixture(scope='module')
# def add_user():
#     def _add_user(user_firstname, user_lastname, user_username, password, admin):
#         user = User(user_firstname=user_firstname,
#                 user_lastname=user_lastname, user_username=user_username, password=password, admin=admin)
#         db.session.add(user)
#         db.session.commit()
#         return user
#     return _add_user
