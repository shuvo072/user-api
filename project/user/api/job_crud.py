from project.user import db
from project.user.models import User,Jobs

def validate_user(resp):
    return User.query.filter_by(user_id=resp).first()

def get_all_jobs(resp):
    return Jobs.query.filter_by(user_id=resp).all()

def get_current_job(resp):
    return Jobs.query.filter_by(user_id=resp,end_year=None).first()

def check_if_user_has_previous_job(uid):
    return Jobs.query.filter_by(user_id=uid).order_by(Jobs.end_year.desc()).all()

def add_job(job_title,company_name,start_year,end_year,user):
    job = Jobs(job_title=job_title, company_name=company_name,
    start_year=start_year,end_year=end_year,user=user)
    db.session.add(job)
    db.session.commit()