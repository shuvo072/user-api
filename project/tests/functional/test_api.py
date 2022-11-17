import json,datetime,jwt
from project.user import db,cache
from project.user.models import User

# def test_clear(test_app,test_admin_database):
#     test_admin_database.session.query(User).delete()
#     return

def test_add_user(test_app, test_admin_database,test_token_generate):
    client = test_app.test_client()
    token = test_token_generate
    headers = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    resp = client.post(
        '/api/users/',
        data=json.dumps({
            "user_firstname":"Shafin",
            "user_lastname":"Hasnat",
            "user_username":"shasnat",
            "password": "123456"
        }),
        headers = headers
    )
    data = json.loads(resp.data.decode())
    assert resp.status_code == 201
    assert 'Shafin Hasnat was added!' in data['message']

def test_single_user(test_app, test_admin_database,test_token_generate):
    token = test_token_generate
    headers = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    user = User(user_firstname='Sayeem',user_lastname='Abdullah',
                user_username='sa1', password='12345', admin=0)
    db.session.add(user)
    db.session.commit()
    client = test_app.test_client()
    resp = client.get(
        f'api/users/{user.user_id}',
        headers=headers)
    data = json.loads(resp.data.decode())
    assert resp.status_code == 200
    assert isinstance(data['ID'],int)
    #assert f'{user.user_id}' in data['ID']
    assert 'Sayeem' in data['First Name']
    assert 'Abdullah' in data['Last Name']
    assert 'sa1' in data['Username']
    # assert f'{user.user_created_at}' in data['Created At']
    # assert f'{user.user_updated_at}' in data['Last Modified']

def test_all_users(test_app, test_admin_database,test_token_generate):
    token = test_token_generate
    headers = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    user1 = User(user_firstname='Mushfiqunnabi',user_lastname='Nijhum',
                user_username='unique1', password='123456', admin=0)
    user2 = User(user_firstname='Shafin',user_lastname='Hasnat',
                user_username='unique2', password='1234', admin=0)
    db.session.add(user1)
    db.session.add(user2)
    db.session.commit()
    client = test_app.test_client()
    resp = client.get(
        'api/users/',
        headers=headers)
    data = json.loads(resp.data.decode())
    assert len(data) == 5
    assert resp.status_code == 200
    assert 'Mushfiqunnabi' in data[3]['First Name']
    assert 'Shafin' in data[4]['First Name']
    assert 'Nijhum' in data[3]['Last Name']
    assert 'Hasnat' in data[4]['Last Name']
    assert 'unique1' in data[3]['Username']
    assert 'unique2' in data[4]['Username']


def test_delete_user(test_app, test_admin_database,test_token_generate):
    token = test_token_generate
    headers = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    user = User(user_firstname='Sayeem',user_lastname='Abdullah',
                user_username='sa2', password='12345', admin=0)
    db.session.add(user)
    db.session.commit()
    client = test_app.test_client()
    resp = client.delete(
        f'api/users/{user.user_id}',
        headers=headers)
    data = json.loads(resp.data.decode())
    assert resp.status_code == 200
    assert f'User {user.user_id} is deleted!' in data['message']


def test_update_user(test_app, test_admin_database,test_token_generate):
    token = test_token_generate
    headers = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    user = User(user_firstname='Sayeem',user_lastname='Abdullah',
                user_username='sa3', password='12345', admin=0)
    db.session.add(user)
    db.session.commit()
    client = test_app.test_client()
    resp = client.put(
        f'api/users/{user.user_id}',
        data=json.dumps({
            "user_firstname":"Sayeem new",
            "user_lastname":"Abdullah new",
            "user_username":"sa4"
        }),
        headers=headers,
        )
    data = json.loads(resp.data.decode())
    assert resp.status_code == 200
    assert f'User Sayeem new Abdullah new is updated!' in data['message']


def test_register_user(test_app, test_admin_database):
    client = test_app.test_client()
    headers = {"Content-Type":"application/json"}
    resp = client.post(
        '/api/register/',
        data=json.dumps({
            "user_firstname":"Sayeem",
            "user_lastname":"Abdullah",
            "user_username":"sa5",
            "password": "123456",
            "admin": 1
        }),
        headers = headers
    )
    data = json.loads(resp.data.decode())
    assert resp.status_code == 201
    assert 'Successfully registered.' in data['message']
    assert len(data['otp'])==6


def test_verify_user(test_app, test_admin_database):
    client = test_app.test_client()
    headers = {"Content-Type":"application/json"}
    resp1 = client.post(
        '/api/register/',
        data=json.dumps({
            "user_firstname":"Sayeem",
            "user_lastname":"Abdullah",
            "user_username":"sa7",
            "password": "123456",
            "admin": 1
        }),
        headers = headers
    )

    resp2 = client.put(
        '/api/verify/',
        data=json.dumps({
            "username":"sa7",
            "otp": cache.get('sa7')
        }),
        headers = headers
    )
    data = json.loads(resp2.data.decode())
    assert resp2.status_code == 200
    assert 'Verified' in data['message']

def test_login_user(test_app, test_admin_database):
    client = test_app.test_client()
    headers = {"Content-Type":"application/json"}
    resp1 = client.post(
        '/api/register/',
        data=json.dumps({
            "user_firstname":"Sayeem",
            "user_lastname":"Abdullah",
            "user_username":"sa8",
            "password": "123456",
            "admin": 1
        }),
        headers = headers
    )
    resp2 = client.put(
        '/api/verify/',
        data=json.dumps({
            "username":"sa8",
            "otp": cache.get('sa8')
        }),
        headers = headers
    )
    resp3 = client.post(
        '/api/login/',
        data=json.dumps({
            "user_username":"sa8",
            "password": "123456"
        }),
        headers = headers
    )
    data = json.loads(resp3.data.decode())
    assert resp3.status_code == 200
    assert isinstance(data['auth_token'],str)
    assert 'Successfully logged in.' in data['message']
    #assert f'{otp_gen}' in data['otp']

def test_verified_user_info(test_app, test_admin_database):
    client = test_app.test_client()
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600),
        'iat': datetime.datetime.utcnow(),
        'sub': 11
    }
    token = jwt.encode(payload,'verysecretkey',algorithm='HS256')
    headers = {"Content-Type":"application/json"}
    headers2 = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    resp1 = client.post(
        '/api/register/',
        data=json.dumps({
            "user_firstname":"Sayeem",
            "user_lastname":"Abdullah",
            "user_username":"sa9",
            "password": "123456",
            "admin": 1
        }),
        headers = headers
    )
    resp2 = client.put(
        '/api/verify/',
        data=json.dumps({
            "username":"sa9",
            "otp": cache.get('sa9')
        }),
        headers = headers
    )

    resp = client.get(
        'api/users/me/',
        headers=headers2)
    data = json.loads(resp.data.decode())
    assert resp.status_code == 200
    assert isinstance(data['data'],object)
    assert 'Verified User' in data['status']

# @pytest.fixture(scope='module')
# def add_user():
#     def _add_user(user_firstname, user_lastname, user_username, password, admin):
#         user = User(user_firstname=user_firstname,
#                 user_lastname=user_lastname, user_username=user_username, password=password, admin=admin)
#         db.session.add(user)
#         db.session.commit()
#         return user
#     return _add_user
