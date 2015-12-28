"""
MongoDB collection schema definition.
"""

import datetime
from . import db
from passlib.apps import custom_app_context as pwd_context


class User(db.Document):
    __tablename__ = 'users'
    username = db.StringField(max_length=32)
    password_hash = db.StringField(max_length=128)
    created_at = db.DateTimeField(default=datetime.datetime.now)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)
