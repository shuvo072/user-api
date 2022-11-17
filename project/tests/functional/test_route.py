import json


def test_home(test_app):
    client = test_app.test_client()
    resp = client.get('/index')
    data = json.loads(resp.data.decode())
    assert resp.status_code == 200
    assert 'Hello World' in data['message']
    assert 'success' in data['status']