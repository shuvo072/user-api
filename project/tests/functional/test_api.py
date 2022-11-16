import json


def test_add_user(test_app, test_database,test_token_generate):
    client = test_app.test_client()
    resp = client.post(
        'api/users/',
        test_token_generate,
        data=json.dumps({
            "user_firstname":"Shafin",
            "user_lastname":"Hasnat",
            "user_username":"shasnat",
            "password": "123456"
        }),
        content_type='application/json',
    )
    data = json.loads(resp.data.decode())
    assert resp.status_code == 201
    assert 'Shafin Hasnat was added!' in data['message']