"""
MongoDB collection schema definition.
"""

import datetime
from . import db
from . import api

from passlib.apps import custom_app_context as pwd_context
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Document):
    __tablename__ = 'users'
    # FIXME: Add self incrementing field and remove SequenceField.
    userid = db.SequenceField(required=True, primary_key=True)
    username = db.StringField(max_length=32, unique=True)
    password_hash = db.StringField(max_length=128)
    created_at = db.DateTimeField(default=datetime.datetime.now)

    def __repr__(self):
        return '<User %r>' % self.username

    def hash_password(self, password):
        # FIXME: decide whether to use passlib or werkzeug hashing?
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        """
        :param expiration: time (in seconds) for token expiration.
        :return:
        """
        s = Serializer(api.config["SECRET_KEY"], expires_in=expiration)
        return s.dumps({'id': self.userid})

    def generate_reset_token(self, expiration=int(datetime.timedelta(days=1).total_seconds())):
        """

        default expiration of 1 day.
        :return:
        """
        s = Serializer(api.config["RESET_SECRET_KEY"], expires_in=expiration)
        # TODO: Add a secret salt here, which can be rechecked upon return, something unique to the user
        return s.dumps({'username': self.username})

    @staticmethod
    def verify_reset_token(reset_token):
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
        s = Serializer(api.config["SECRET_KEY"])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None             # valid but expired token.
        except BadSignature:
            return None             # invalid token.

        user = User.objects(userid=data['id']).first()
        return user
