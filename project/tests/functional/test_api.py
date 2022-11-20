import json,datetime,jwt
from project.user import db,cache
from project.user.models import User,Jobs

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

def test_no_user(test_app, test_admin_database,test_token_generate):
    token = test_token_generate
    headers = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    user = User(user_firstname='Sayeem',user_lastname='Abdullah',
                user_username='unique3', password='12345', admin=0)
    db.session.add(user)
    db.session.commit()
    client = test_app.test_client()
    resp = client.get(
        f'api/users/25',
        headers=headers)
    data = json.loads(resp.data.decode())
    assert resp.status_code == 404
    assert 'User does not exist!' in data['message']
    resp2 = client.delete(
        f'api/users/25',
        headers=headers)
    data2 = json.loads(resp2.data.decode())
    assert resp2.status_code == 404
    assert 'User 25 does not exist!' in data2['message']
    resp3 = client.put(
        f'api/users/25',
        data=json.dumps({
            "user_firstname":"Sayeem new",
            "user_lastname":"Abdullah new",
            "user_username":"unique4"
        }),
        headers=headers,
        )
    data3 = json.loads(resp3.data.decode())
    assert resp3.status_code == 404
    assert 'User 25 does not exist!' in data3['message']   



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


def test_not_admin(test_app, test_admin_database):
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600),
        'iat': datetime.datetime.utcnow(),
        'sub': 2
    }
    token = jwt.encode(payload,'verysecretkey',algorithm='HS256')
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
    assert resp.status_code == 404
    assert 'You are not admin' in data['message']


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

def test_failed_register_user(test_app, test_admin_database):
    client = test_app.test_client()
    headers = {"Content-Type":"application/json"}
    resp = client.post(
        '/api/register/',
        data=json.dumps({
            "user_firstname":"Sayeem",
            "user_lastname":"Abdullah",
            "user_username":"shuvo72",
            "password": "123456",
            "admin": 1
        }),
        headers = headers
    )
    data = json.loads(resp.data.decode())
    assert resp.status_code == 202
    assert 'User already exists. Please Log in.' in data['message']



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


def test_failed_verify_user(test_app, test_admin_database):
    client = test_app.test_client()
    headers = {"Content-Type":"application/json"}
    resp1 = client.post(
        '/api/register/',
        data=json.dumps({
            "user_firstname":"Sayeem",
            "user_lastname":"Abdullah",
            "user_username":"unique6",
            "password": "123456",
            "admin": 1
        }),
        headers = headers
    )

    resp2 = client.put(
        '/api/verify/',
        data=json.dumps({
            "username":"unique6",
            "otp": "123"
        }),
        headers = headers
    )
    data = json.loads(resp2.data.decode())
    assert resp2.status_code == 401
    assert 'Provide a valid otp.' in data['message']


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


def test_failed_login_user(test_app, test_admin_database):
    client = test_app.test_client()
    headers = {"Content-Type":"application/json"}
    resp1 = client.post(
        '/api/register/',
        data=json.dumps({
            "user_firstname":"Sayeem",
            "user_lastname":"Abdullah",
            "user_username":"unique7",
            "password": "123456",
            "admin": 1
        }),
        headers = headers
    )
    resp2 = client.put(
        '/api/verify/',
        data=json.dumps({
            "username":"unique7",
            "otp": "1234"
        }),
        headers = headers
    )
    resp3 = client.post(
        '/api/login/',
        data=json.dumps({
            "user_username":"unique7",
            "password": "123456"
        }),
        headers = headers
    )
    data = json.loads(resp3.data.decode())
    assert resp3.status_code == 404
    assert 'Verify yourself first' in data['message']

    resp4 = client.post(
        '/api/login/',
        data=json.dumps({
            "user_username":"unique7",
            "password": "1234567"
        }),
        headers = headers
    )
    data2 = json.loads(resp4.data.decode())
    assert resp4.status_code == 404
    assert 'Wrong Username or Password' in data2['message']

    resp5 = client.post(
        '/api/login/',
        data=json.dumps({
            "user_username":"nouser",
            "password": "1234568"
        }),
        headers = headers
    )
    data3 = json.loads(resp5.data.decode())
    assert resp5.status_code == 500
    assert 'No user available' in data3['message']    


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


def test_verified_user_info_with_job(test_app, test_admin_database):
    client = test_app.test_client()
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600),
        'iat': datetime.datetime.utcnow(),
        'sub': 12
    }
    token = jwt.encode(payload,'verysecretkey',algorithm='HS256')
    headers = {"Content-Type":"application/json"}
    headers2 = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    resp1 = client.post(
        '/api/register/',
        data=json.dumps({
            "user_firstname":"Sayeem",
            "user_lastname":"Abdullah",
            "user_username":"unique8",
            "password": "123456",
            "admin": 1
        }),
        headers = headers
    )
    resp2 = client.put(
        '/api/verify/',
        data=json.dumps({
            "username":"unique8",
            "otp": cache.get('unique8')
        }),
        headers = headers
    )
    resp3 = client.post(
        '/api/job/',
        data=json.dumps({
            "job_title":"Software Engineer",
            "company_name":"Intercloud Limited",
            "start_year":"2022"
        }),
        headers = headers2
    )

    resp = client.get(
        'api/users/me/',
        headers=headers2)
    data = json.loads(resp.data.decode())
    assert resp.status_code == 200
    assert isinstance(data['data'],object)
    assert 'Verified User' in data['status']


def test_wrong_token(test_app, test_admin_database,test_token_generate):
    client = test_app.test_client()
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600),
        'iat': datetime.datetime.utcnow(),
        'sub': 12
    }
    token = jwt.encode(payload,'verysecretkey',algorithm='HS256')
    token2 = ''
    headers = {"Content-Type":"application/json"}
    headers2 = {"Content-Type":"application/json", "Authorization": f"Bearer {token2}"}
    resp1 = client.post(
        '/api/register/',
        data=json.dumps({
            "user_firstname":"Sayeem",
            "user_lastname":"Abdullah",
            "user_username":"sa10",
            "password": "123456",
            "admin": 1
        }),
        headers = headers
    )
    resp2 = client.put(
        '/api/verify/',
        data=json.dumps({
            "username":"sa10",
            "otp": cache.get('sa10')
        }),
        headers = headers
    )

    resp = client.get(
        'api/users/me/',
        headers=headers2)
    data = json.loads(resp.data.decode())
    assert resp.status_code == 401
    assert 'Provide a valid auth token.' in data['message']


def test_create_job(test_app, test_admin_database,test_token_generate):
    client = test_app.test_client()
    token = test_token_generate
    token2 = ''
    headers = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    headers2 = {"Content-Type":"application/json", "Authorization": f"Bearer {token2}"}
    resp = client.post(
        '/api/job/',
        data=json.dumps({
            "job_title":"Software Engineer",
            "company_name":"Intercloud Limited",
            "start_year":"2022"
        }),
        headers = headers
    )
    data = json.loads(resp.data.decode())
    assert resp.status_code == 201
    assert 'Job added!' in data['message']
    resp2 = client.post(
        '/api/job/',
        data=json.dumps({
            "job_title":"Software Engineer",
            "company_name":"Intercloud Limited",
            "start_year":"2022"
        }),
        headers = headers2
    )
    data2 = json.loads(resp2.data.decode())
    assert resp2.status_code == 403
    assert 'Not Valid Token' in data2['message']

def test_create_job_already_has_a_job(test_app, test_admin_database,test_token_generate):
    client = test_app.test_client()
    token = test_token_generate
    headers = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    resp = client.post(
        '/api/job/',
        data=json.dumps({
            "job_title":"Software Engineer",
            "company_name":"Intercloud Limited",
            "start_year":"2022"
        }),
        headers = headers
    )
    resp2 = client.post(
        '/api/job/',
        data=json.dumps({
            "job_title":"Senior Software Engineer",
            "company_name":"Intercloud Limited",
            "start_year":"2023"
        }),
        headers = headers
    )   
    data = json.loads(resp2.data.decode())
    assert resp2.status_code == 201
    assert 'Job added!' in data['message']


def test_current_job(test_app, test_admin_database,test_token_generate):
    client = test_app.test_client()
    token = test_token_generate
    token2 = ''
    headers = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    headers2 = {"Content-Type":"application/json", "Authorization": f"Bearer {token2}"}
    resp1 = client.post(
        '/api/job/',
        data=json.dumps({
            "job_title":"Software Engineer",
            "company_name":"Intercloud Limited",
            "start_year":"2022"
        }),
        headers = headers
    )

    resp = client.get(
        'api/job/current/',
        headers=headers)
    data = json.loads(resp.data.decode())
    assert resp.status_code == 200
    assert isinstance(data['data'],object)
    assert 'Current Job' in data['status']

    resp2 = client.get(
        'api/job/current/',
        headers=headers2)
    data2 = json.loads(resp2.data.decode())
    assert resp2.status_code == 403
    assert 'Not Valid Token' in data2['message']   


def test_job_history(test_app, test_admin_database,test_token_generate):
    client = test_app.test_client()
    token = test_token_generate
    token2 = ''
    headers = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    headers2 = {"Content-Type":"application/json", "Authorization": f"Bearer {token2}"}
    resp1 = client.post(
        '/api/job/',
        data=json.dumps({
            "job_title":"Software Engineer",
            "company_name":"Intercloud Limited",
            "start_year":"2022"
        }),
        headers = headers
    )
    resp2 = client.post(
        '/api/job/',
        data=json.dumps({
            "job_title":"Senior Software Engineer",
            "company_name":"Intercloud Limited",
            "start_year":"2023"
        }),
        headers = headers
    )    

    resp = client.get(
        'api/job/history/',
        headers=headers)
    data = json.loads(resp.data.decode())
    assert resp.status_code == 200
    assert len(data) == 4
    assert 'Software Engineer' in data[1]['Job Title']
    assert 'Senior Software Engineer' in data[2]['Job Title']
    assert 'Intercloud Limited' in data[1]['Company Name']
    assert 'Intercloud Limited' in data[2]['Company Name']
    assert '2022' in data[1]['Start Year']
    assert '2023' in data[2]['Start Year']

    resp2 = client.get(
        'api/job/history/',
        headers=headers2)
    data2 = json.loads(resp2.data.decode())
    assert resp2.status_code == 403
    assert 'Not Valid Token' in data2['message']   