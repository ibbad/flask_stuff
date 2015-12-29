from flask import Flask, request, abort, jsonify, g
from flask.ext.mongoengine import MongoEngine
from flask.ext.httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
import datetime


api = Flask(__name__)
api.config["MONGODB_SETTINGS"] = {'DB': 'test_db'}
api.config["SECRET_KEY"] = "$3cR3tK3Y"

db = MongoEngine(api)
auth = HTTPBasicAuth()

class User(db.Document):
    __tablename__ = 'users'
    # FIXME: Add self incrementing field and remove SequenceField.
    userid = db.SequenceField(required=True, primary_key=True)
    username = db.StringField(max_length=32, unique=True)
    password_hash = db.StringField(max_length=128)
    created_at = db.DateTimeField(default=datetime.datetime.now)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        """
        :param expiration: time (in seconds) for token expiration.
        :return:
        """
        s = Serializer(api.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.userid})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(api.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None             # valid but expired token.
        except BadSignature:
            return None             # invalid token.

        user = User.objects(userid=data['id'])
        return user

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
    print "here"
    user = User.objects(userid=id).first()
    print "here2"
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
    print "here1"
    token = g.user.generate_auth_token(600)
    print "here2"
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


if __name__ == "__main__":
    api.run(debug=True)