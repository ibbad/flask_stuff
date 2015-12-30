from flask import Flask, request, abort, jsonify, g
from flask.ext.mongoengine import MongoEngine
from flask.ext.httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string


api = Flask(__name__)
api.config["MONGODB_SETTINGS"] = {'DB': 'test_db'}
api.config["SECRET_KEY"] = "$3cR3tK3Y"
api.config["RESET_SECRET_KEY"] = "@ V3Ry $3cR3t k3Y"

db = MongoEngine(api)
auth = HTTPBasicAuth()

class User(db.Document):
    """
    User document to store user information i.e. username and password.
    primary key: userid (integer)
    username: user provided username (unique)
    """
    __tablename__ = 'users'
    # FIXME: decide whether to keep userid it primary key or not.
    userid = db.SequenceField(parimary_key=True)
    username = db.StringField(max_length=32, unique=True)
    password_hash = db.StringField(max_length=128)
    created_at = db.DateTimeField(default=datetime.datetime.now)

    def __repr__(self):
        return '<User %r>' % self.username

    def __str__(self):
        return self.username

    def hash_password(self, password):
        """
        Hash user password to store in database.
        :param password:
        :return:
        """
        # TODO: werkzeug hashing can be used instead of passlib
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        """
        Verify user password
        :param user password
        :return: True (if verified), else False
        """
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=int(datetime.timedelta(hours=1).total_seconds())):
        """
        Generated authentication token with default expiration of 1 hours.
        :return: authentication token.
        """
        s = Serializer(api.config["SECRET_KEY"], expires_in=expiration)
        return s.dumps({'username': self.username})

    def generate_reset_token(self, expiration=int(datetime.timedelta(days=1).total_seconds())):
        """
        Generated token for password reset request with default expiration of 1 day.
        :param expiration: token expiry limit, in seconds.
        :return: password reset token.
        """
        s = Serializer(api.config["RESET_SECRET_KEY"], expires_in=expiration)
        # TODO: Add a secret salt here, which can be rechecked upon return, something unique to the user
        return s.dumps({'username': self.username})

    @staticmethod
    def verify_reset_token(reset_token):
        """
        Verify the password reset token.
        :param reset_token: token generated for password reset request.
        :return: user document for whom the token was generated.
        """
        s = Serializer(api.config["RESET_SECRET_KEY"])
        try:
            data = s.loads(reset_token)
        except SignatureExpired:
            return None             # token expired.
        except BadSignature:
            return None             # invalid token

        user = User.objects(username=data['username']).first()
        return user

    @staticmethod
    def verify_auth_token(token):
        """
        Verify the authentication token.
        :param token: authentication token
        :return: user document for whom the token was generated.
        """
        s = Serializer(api.config["SECRET_KEY"])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None             # valid but expired token.
        except BadSignature:
            return None             # invalid token.

        user = User.objects(username=data['username']).first()
        return user

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
        abort(400)      # missing arguments
    if len(User.objects(username=username)) > 0:
        abort(400)      # user already exists.

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
        abort(400)
    return jsonify({'username': user.username})

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
    token = g.user.generate_auth_token(expiration=datetime.timedelta(hours=12))
    return jsonify({'token': token.decode('ascii'), 'Validity': 600})

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
        abort(400)          # no username provided.
    user = User.objects(username=username).first()
    if user is None:
        abort(400)          # no user found.
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
        abort(400)          # no user found provided.
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
        abort(400)          # not a valid user
    # Generate a random password and send it back to the user.
    random_pwd = ''.join(random.SystemRandom().
                         choice(string.ascii_uppercase
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
        abort(400)          # not a valid user
    user.hash_password(new_password)
    user.save()
    return jsonify({'password_changed': 'success'}), 201

if __name__ == "__main__":
    api.run(debug=True)