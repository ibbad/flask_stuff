from flask import request, abort, jsonify
from . import api
from .models import User


@api.route('/')
def index():
    return "Hello, world"

@api.route('/index')
def index_v1():
    return "Hello, world\n"

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


