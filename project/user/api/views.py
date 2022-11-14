import secrets
from project.user.models import User
from flask import request,jsonify, make_response
from project.user import db, bcrypt, cache
from flask.views import MethodView
from project.user.api import user_api_blueprint,auth_blueprint,verified_user_blueprint,job_blueprint,job_history_blueprint

# Admin decorator
def admin_required(f):
    def decorator(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(user_id=resp).first()
                if user.admin==True:
                    return f(*args, **kwargs)
                else:
                    responseObject = {
                        'status': 'failed',
                        'message': 'You are not admin'
                    }
                    return make_response(jsonify(responseObject)), 404
    return decorator


class UserAPI(MethodView):
    
    @admin_required
    def get(self, id):
        if id is None:
            users = User.query.all()
            data = []
            for user in users:
                data.append({
                    "ID": user.user_id,
                    "First Name": user.user_firstname,
                    "Last Name": user.user_lastname,
                    "Username": user.user_username,
                    "Created At": user.user_created_at,
                    "Last Modified": user.user_updated_at
                })
            return data, 200
            
        else:
            user = User.query.filter_by(user_id=id).first()
            data_user = []
            data_user.append({
                "ID": user.user_id,
                "First Name": user.user_firstname,
                "Last Name": user.user_lastname,
                "Username": user.user_username,
                "Created At": user.user_created_at,
                "Last Modified": user.user_updated_at
                })
            return data_user, 200
                    
    @admin_required
    def post(self):
                #"Creates a new user!"
        post_data = request.get_json()
        user_firstname = post_data.get('user_firstname')
        user_lastname = post_data.get('user_lastname')
        user_username = post_data.get('user_username')
        password = post_data.get('password')

        db.session.add(User(user_firstname=user_firstname, user_lastname=user_lastname,
        user_username=user_username,password=password))
        db.session.commit()

        response_object = {
            'message': f'{user_firstname} {user_lastname} was added!'
        }
        return response_object, 201

    @admin_required    
    def delete(self, id):
                #  "Deletes a user by id!"
        user = User.query.filter_by(user_id=id).first()
        if not user:
            response_object = {
                'message': f'User {id} does not exist!'
            }
            return response_object, 400

        db.session.delete(user)
        db.session.commit()

        response_object = {
            'message': f'User {id} is deleted!'
        }
        return response_object, 200
    
    @admin_required
    def put(self, id):
                # "Updates a user by id!"
        post_data = request.get_json()
        user_firstname = post_data.get('user_firstname')
        user_lastname = post_data.get('user_lastname')
        user_username = post_data.get('user_username')
        user = User.query.filter_by(user_id=id).first()

        if not user:
            response_object = {
                'message': f'User {id} does not exist!'
            }
            return response_object, 404 #! Not found should be 404 !#
            
        user.user_firstname = user_firstname
        user.user_lastname = user_lastname
        user.user_username = user_username
        db.session.commit()

        response_object = {
            'message': f'User {user_firstname} {user_lastname} is updated!'
        }
        return response_object, 200

user_view = UserAPI.as_view('User_Api')

#* No need of 3 lines, one can accomplish the job *#

user_api_blueprint.add_url_rule('/api/users/', defaults={'id': None}, view_func=user_view,methods=['GET', 'POST'])
#user_api_blueprint.add_url_rule('/api/users/', view_func=user_view,methods=['POST'])
user_api_blueprint.add_url_rule('/api/users/<int:id>', view_func=user_view,methods=['GET', 'PUT', 'DELETE'])


class RegisterAPI(MethodView):
    def post(self):
        # Register User #
        post_data = request.get_json()
        user = User.query.filter_by(user_username=post_data.get('user_username')).first()
        otp_gen=secrets.token_hex(3)
        cache.set(post_data.get('user_username'),otp_gen)
        if not user:
            try:
                user = User(
                    user_firstname=post_data.get('user_firstname'),
                    user_lastname=post_data.get('user_lastname'),
                    user_username=post_data.get('user_username'),
                    password=post_data.get('password'),
                    admin=post_data.get('admin')
                )

                db.session.add(user)
                db.session.commit()

                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'otp': otp_gen
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202


class LoginAPI(MethodView):
    def post(self):
        # Login User #
        post_data = request.get_json()
        try:
            user = User.query.filter_by(user_username=post_data.get('user_username')).first()
            auth_token = user.encode_auth_token(user.user_id)
            if user and bcrypt.check_password_hash(
                user.password, post_data.get('password')
            ):
                if user.verified==True:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token
                    }
                    return make_response(jsonify(responseObject)), 200
                else:
                    responseObject = {
                        'status': 'failed',
                        'message': 'Verify yourself first'
                    }
                    return make_response(jsonify(responseObject)), 404
            else:
                responseObject = {
                        'status': 'failed',
                        'message': 'Wrong Username or Password'
                    }
                return make_response(jsonify(responseObject)), 404
            #! No condition for wrong password !#

        except Exception as e:
            print(e)
            responseObject = {
                'status': 'failed',
                'message': 'No user available'
            }
            return make_response(jsonify(responseObject)), 500


class VerifyAPI(MethodView):
    # Verify using otp #
    def put(self):
        post_data = request.get_json()
        username = post_data.get('username')
        otp = post_data.get('otp')
        redis_otp = cache.get(username)
        user = User.query.filter_by(user_username=username).first()
        if redis_otp==otp:
            user.active = True
            user.verified = True
            db.session.commit()
            responseObject = {
                'status': 'success',
                'message': 'Verified'
            }
            cache.clear()
            return make_response(jsonify(responseObject)), 200
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid otp.'
            }
            return make_response(jsonify(responseObject)), 401

#! Not needed. Admin will call previous CRUD api only. !#

registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
verify_view = VerifyAPI.as_view('verify_api')

auth_blueprint.add_url_rule('/api/register/',view_func=registration_view,methods=['POST'])
auth_blueprint.add_url_rule('/api/login/',view_func=login_view,methods=['POST'])
auth_blueprint.add_url_rule('/api/verify/',view_func=verify_view,methods=['PUT'])


class VerifiedUserAPI(MethodView):
    def get(self):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(user_id=resp).first()
                responseObject = {
                    'status': 'Verified User',
                    'data': {
                        "ID": user.user_id,
                        "First Name": user.user_firstname,
                        "Last Name": user.user_lastname,
                        "Username": user.user_username,
                        "Created At": user.user_created_at,
                        "Last Modified": user.user_updated_at
                    }
                }
                return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


verifiedUserData_view = VerifiedUserAPI.as_view('verifiedUser_api')
verified_user_blueprint.add_url_rule('/api/users/me/',view_func=verifiedUserData_view,methods=['GET'])


class JobAPI(MethodView):
    def post(self):
        return "Job added"
    
    def get(self):
        return "Current Job"


job_view = JobAPI.as_view('job-api')
job_blueprint.add_url_rule('/api/job/',view_func=job_view,methods=['POST'])
job_blueprint.add_url_rule('/api/job/current/',view_func=job_view,methods=['GET'])


class JobHistoryAPI(MethodView):
    def get(self):
        return "history fetched"


jobHistory_view = JobHistoryAPI.as_view('job-history-api')
job_history_blueprint.add_url_rule('/api/job/history/',view_func=jobHistory_view,methods=['GET'])