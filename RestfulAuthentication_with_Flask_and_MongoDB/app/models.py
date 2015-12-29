"""
MongoDB collection schema definition.
"""

import datetime
from . import db
from . import api
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired


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
