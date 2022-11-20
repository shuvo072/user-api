import json,datetime,jwt,pytest,project.user.api.views
from project.user import db,cache
from project.user.models import User,Jobs

def test_create_job(test_app, monkeypatch,test_token_generate):
    def mock_validate_user(resp):
        return User(user_firstname="Mehadi Hasan",user_lastname="Shuvo",
        user_username='shuvo72',
        password='123456'
        )

    def mock_check_if_user_has_previous_job(uid):
        return False

    def mock_create_job(job_title,company_name,start_year,end_year,user):
        return True

    monkeypatch.setattr(project.user.api.views, "validate_user", mock_validate_user)
    monkeypatch.setattr(project.user.api.views, "check_if_user_has_previous_job", mock_check_if_user_has_previous_job)
    monkeypatch.setattr(project.user.api.views, "add_job", mock_create_job)

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
    data = json.loads(resp.data.decode())
    assert resp.status_code == 201
    assert 'Job added!' in data['message']


def test_current_job(test_app, monkeypatch, test_token_generate):
    def mock_validate_user(resp):
        return User(user_firstname="Mehadi Hasan",user_lastname="Shuvo",
        user_username='shuvo72',
        password='123456'
        )

    def mock_check_if_user_has_previous_job(uid):
        return False
    
    def mock_create_job(job_title,company_name,start_year,end_year,user):
        return True

    def mock_current_job(resp):
        return Jobs(job_title="Software Enginner",
        company_name="Intercloud Limited",
        start_year="2022",
        end_year=None,user=User(user_firstname="Mehadi Hasan",user_lastname="Shuvo",
        user_username='shuvo72',
        password='123456'
        ))

    monkeypatch.setattr(project.user.api.views, "validate_user", mock_validate_user)
    monkeypatch.setattr(project.user.api.views, "check_if_user_has_previous_job", mock_check_if_user_has_previous_job)
    monkeypatch.setattr(project.user.api.views, "add_job", mock_create_job)
    monkeypatch.setattr(project.user.api.views, "get_current_job", mock_current_job)
    client = test_app.test_client()
    token = test_token_generate
    headers = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    # resp1 = client.post(
    #     '/api/job/',
    #     data=json.dumps({
    #         "job_title":"Software Engineer",
    #         "company_name":"Intercloud Limited",
    #         "start_year":"2022"
    #     }),
    #     headers = headers
    # )
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


def test_all_jobs(test_app, monkeypatch, test_token_generate):
    def mock_validate_user(resp):
        return User(user_firstname="Mehadi Hasan",user_lastname="Shuvo",
        user_username='shuvo72',
        password='123456'
        )

    def mock_check_if_user_has_previous_job(uid):
        return False
    
    def mock_create_job(job_title,company_name,start_year,end_year,user):
        return True

    def mock_all_jobs(resp):
        return [Jobs(job_title="Software Engineer",
        company_name="Intercloud Limited",
        start_year="2022",
        end_year=None,user=User(user_firstname="Mehadi Hasan",user_lastname="Shuvo",
        user_username='shuvo72',
        password='123456'
        )),Jobs(job_title="Software Engineer",
        company_name="Intercloud Limited",
        start_year="2022",
        end_year=None,user=User(user_firstname="Mehadi Hasan",user_lastname="Shuvo",
        user_username='shuvo72',
        password='123456'
        ))]

    monkeypatch.setattr(project.user.api.views, "validate_user", mock_validate_user)
    monkeypatch.setattr(project.user.api.views, "check_if_user_has_previous_job", mock_check_if_user_has_previous_job)
    monkeypatch.setattr(project.user.api.views, "add_job", mock_create_job)
    monkeypatch.setattr(project.user.api.views, "get_all_jobs", mock_all_jobs)
    client = test_app.test_client()
    token = test_token_generate
    headers = {"Content-Type":"application/json", "Authorization": f"Bearer {token}"}
    # resp1 = client.post(
    #     '/api/job/',
    #     data=json.dumps({
    #         "job_title":"Software Engineer",
    #         "company_name":"Intercloud Limited",
    #         "start_year":"2022"
    #     }),
    #     headers = headers
    # )

    resp = client.get(
        'api/job/history/',
        headers=headers)
    data = json.loads(resp.data.decode())
    assert resp.status_code == 200
    assert len(data) == 2
    assert 'Software Engineer' in data[0]['Job Title']
