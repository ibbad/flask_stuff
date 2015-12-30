"""
MongoDB collection schema definition.
"""

import datetime
from . import db
from . import api

from passlib.apps import custom_app_context as pwd_context
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired


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
