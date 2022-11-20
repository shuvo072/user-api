from dataclasses import dataclass
import jwt,secrets
from flask import current_app
from project.user import db,bcrypt
import datetime
@dataclass
class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key = True, autoincrement=True)
    user_firstname = db.Column(db.String(120), index = True, nullable=False)
    user_lastname = db.Column(db.String(120), index = True, nullable=False)
    user_username = db.Column(db.String(64), index = True, unique = True, nullable=False)
    password = db.Column(db.String(128),nullable = False)
    user_created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    user_updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    admin = db.Column(db.Boolean, nullable = False, default = False)
    active = db.Column(db.Boolean, nullable = False, default = False)
    verified = db.Column(db.Boolean, nullable = False, default = False)
    #* OTP should be cached. Since user doesn't need them after verifying *#
    jobs = db.relationship('Jobs', backref = 'job_holder', lazy = 'select')

    def encode_auth_token(self, user_id):
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                current_app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        try:
            payload = jwt.decode(auth_token, current_app.config.get('SECRET_KEY'), algorithms='HS256',verify=True)
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'

    def __init__(self, user_firstname, user_lastname, user_username,
    password, admin=False, active=False, verified = False):
        self.user_firstname = user_firstname
        self.user_lastname = user_lastname
        self.user_username = user_username
        self.password = bcrypt.generate_password_hash(
            password, current_app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.admin = admin
        self.active = active
        self.verified = verified
    
    def __repr__(self):
        #* Use f-string instead of format *#
        return f"<User {self.user_id} : {self.user_firstname} {self.user_lastname} {self.user_username} {self.user_created_at} {self.user_updated_at}>"

@dataclass
class Jobs(db.Model):
    __tablename__ = 'jobs'
    job_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    job_title = db.Column(db.String(120), index = True, nullable=False)
    company_name = db.Column(db.String(120), index = True, nullable=False)
    start_year = db.Column(db.String(5), nullable=False)
    end_year = db.Column(db.String(5)) 
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))

    def __init__(self, job_title, company_name, start_year,
    end_year,user):  
        self.job_title = job_title
        self.company_name = company_name
        self.start_year = start_year
        self.end_year = end_year
        self.job_holder=user


    def __repr__(self):
        return f"<Job {self.job_id} : {self.job_title} {self.company_name} {self.start_year} {self.end_year}>"