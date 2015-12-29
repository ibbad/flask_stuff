from flask import request, abort, jsonify, g
from . import api
from .models import User
from flask.ext.httpauth import HTTPBasicAuth
import random
import string

auth = HTTPBasicAuth()

@api.route('/')
def index():
    return "Hello, world"

@api.route('/index')
def index_v1():
    return "Hello, world\n"

@auth.verify_password
def verify_password(username_or_token, password):
    # Try to authenticate using token, at first.
    user = User.verify_auth_token(username_or_token)
    if not user:
        # Token authentication failed, use basic authentication.
        user = User.objects(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@api.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)      # missing arguments
    if len(User.objects(username=username)) > 0:
        abort(400)      # user already exists.
    # print User.objects(username=username)
    user = User(username=username)
    user.hash_password(password)
    user.save()
    return jsonify({'username': user.username}), 201

@api.route('/api/users/<int:id>')
@auth.login_required
def get_user(id):
    user = User.objects(userid=id).first()
    if user is None:              # no user found
        abort(400)
    return jsonify({'username': user.username})

@api.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s' % g.user.username})

@api.route('/api/token')
@auth.login_required            # username and password required.
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})

@api.route('/api/user/changepwd', methods=['POST'])
@auth.login_required
def change_password():
    user = g.user
    new_password = request.json.get('password')
    user.hash_password(new_password)
    user.save()
    return jsonify({'username': user.username, 'password_changed': 'success'}), 202

@api.route('/api/user/request_reset_password', methods=['POST'])
def get_reset_token():
    username = request.json.get('username')
    if username is None:
        abort(400)          # no username provided.
    user = User.objects(username=username).first()
    if user is None:
        abort(400)          # no user found.
    reset_token = user.generate_reset_token()
    return jsonify({'reset-password-token': reset_token.decode('ascii'), 'duration': '1 day'})

@api.route('/api/user/v1.0/reset_password', methods=['POST'])
def reset_password_v1():
    """
    When user gets a randomly generated password upon request for password change.
    :return:
    """
    reset_token = request.json.get('rst_token')
    user = User.verify_reset_token(reset_token)
    if user is None:
        abort(400)          # not a valid user
    # Generate a random password and send it back to the user.
    random_pwd = ''.join(random.SystemRandom().
                         choice(string.ascii_uppercase+string.digits+string.ascii_lowercase)
                         for _ in range(16))
    user.hash_password(random_pwd)
    user.save()
    return jsonify({'new_password': random_pwd}), 201

@api.route('/api/user/v1.1/reset_password', methods=['POST'])
def reset_password_v2():
    """
    When user provides the new password.
    :return:
    """
    reset_token = request.json.get('rst_token')
    new_password = request.json.get('password')
    user = User.verify_reset_token(reset_token)
    if user is None:
        abort(400)          # not a valid user
    user.hash_password(new_password)
    user.save()
    return jsonify({'password_changed': 'success'}), 201
