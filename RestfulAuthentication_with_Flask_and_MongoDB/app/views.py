from flask import request, abort, jsonify, g
from . import api
from .models import User
from flask.ext.httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

@api.route('/')
def index():
    return "Hello, world"

@api.route('/index')
def index_v1():
    return "Hello, world\n"

@auth.verify_password
def verify_password(username, password):
    user = User.objects(username=username).first()
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
def get_user(id):
    user = User.objects(id=id)
    if not user:
        abort(400)              # no user found
    return jsonify({'username': user.username})

@api.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s' % g.user.username})



