from flask import request, abort, jsonify, g
from . import api
from .models import User
from flask.ext.httpauth import HTTPBasicAuth
import random
import string

auth = HTTPBasicAuth()

@api.route('/')
@api.route('/index')
def index():
    return "Hello, world"

@auth.verify_password
def verify_password(username_or_token, password):
    """
    Verify user password or authentication token provided by user.
    :param username_or_token: username or authentication token.
    :param password: user provided password, no password in case of authentication token.
    :return: True if user authenticated, else False
    """
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
    """
    Register new user with username, password provided in the request.
    :return:
    """
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        return jsonify({'Error': 'Username, password not provided'}), 400
    if len(User.objects(username=username)) > 0:
        return jsonify({'Error': 'Specified username already exists'}), 400
    user = User(username=username)
    user.hash_password(password)
    user.save()
    return jsonify({'userid': user.userid, 'username': user.username}), 201

@api.route('/api/users/<int:id>')
@auth.login_required
def get_user(id):
    """
    Get user with unique user id.
    :param id: user id (integer)
    :return:
    """
    user = User.objects(userid=id).first()
    if user is None:              # no user found
        return jsonify({'Error': 'No user found'}), 404
    return jsonify({'username': user.username})

@api.route('/api/user/delete', methods=['DELETE'])
@auth.login_required
def delete_user():
    success = User.objects(username=g.user.username).delete()
    if success:
        return jsonify({'Status': 'user deleted'}), 302
    else:
        return jsonify({'Error': 'User not found'}), 404


@api.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s' % g.user.username})

@api.route('/api/token')
@auth.login_required            # username and password required.
def get_auth_token():
    """
    Request authentication token for logged in user.
    :return: authentication token for the user.
    """
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii'), 'Validity': '12 hours'})

@api.route('/api/user/change_password', methods=['PUT'])
@auth.login_required
def change_password():
    """
    Change user password, new password provided in the request.
    :parameter password: new password provided by the user.
    """
    user = g.user
    new_password = request.json.get('password')
    user.hash_password(new_password)
    user.save()
    return jsonify({'username': user.username, 'password_changed': 'success'}), 202

@api.route('/api/user/request_reset_password', methods=['PUT'])
def get_reset_token():
    """
    Get password reset token for the user for the user
    :parameter username: provided in the request.
    :return: reset_token: password reset token to be provided by the user with reset request.
    """
    username = request.json.get('username')
    if username is None:
        return jsonify({'Error': 'No username provided in the reset password request'}), 400
    user = User.objects(username=username).first()
    if user is None:
        return jsonify({'error': 'Specified user not found'}), 404
    reset_token = user.generate_reset_token()
    return jsonify({'reset-password-token': reset_token.decode('ascii'), 'Validity': '1 hour'})

@api.route('/api/user/<int:id>/request_reset_password', methods=['GET'])
def get_reset_token_v1(id):
    """
    Get password reset token for the user for the user:
    :para id: user remembers his userid.
    :return: reset_token: password reset token to be provided by the user with reset request.
    """
    user = User.objects(userid=id).first()
    if User is None:
        return jsonify({'error': 'Invalid user'}), 400
    reset_token = user.generate_reset_token()
    return jsonify({'reset-password-token': reset_token.decode('ascii'), 'Validity': '1 hour'})

@api.route('/api/user/v1.0/reset_password', methods=['PUT'])
def reset_password_v1():
    """
    When user gets a randomly generated password upon request for password change.
    :parameter reset_token: password reset token issued to the user.
    :return: randomly generated password.
    """
    reset_token = request.json.get('pwd_rst_token')
    if reset_token is None:
        return jsonify({'error': 'Please provide password reset token with the request'}), 400
    user = User.verify_reset_token(reset_token)
    if user is None:
        return jsonify({'error': 'Invalid token'}), 400

    # Generate a random password and send it back to the user.
    random_pwd = ''.join(random.SystemRandom().choice(string.ascii_uppercase
                                                      + string.digits
                                                      + string.ascii_lowercase)
                         for _ in range(16))
    user.hash_password(random_pwd)
    user.save()
    return jsonify({'new_password': random_pwd}), 201

@api.route('/api/user/v1.1/reset_password', methods=['PUT'])
def reset_password_v2():
    """
    User password is reset to new password provided by the user.
    :parameter rst_token: password reset token issued to user.
    :parameter password: new password provided by the user.
    :return:
    """
    reset_token = request.json.get('pwd_rst_token')
    if reset_token is None:
        return jsonify({'error': 'Please provide password reset token with the request'}), 400
    new_password = request.json.get('password')
    user = User.verify_reset_token(reset_token)
    if user is None:
        return jsonify({'error': 'Invalid token'}), 400
    user.hash_password(new_password)
    user.save()
    return jsonify({'status': 'password changed successfully'}), 201
    user.hash_password(new_password)
    user.save()
    return jsonify({'password_changed': 'success'}), 201
