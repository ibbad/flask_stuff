"""
Initialization
"""

from flask import Flask
from flask.ext.mongoengine import MongoEngine

api = Flask(__name__)
api.config["MONGODB_SETTINGS"] = {'DB': 'test_db'}
api.config["SECRET_KEY"] = "$3cR3tK3Y"

db = MongoEngine(api)

from . import views             # to avoid circular import

if __name__ == "__main__":
    api.debug = True
    api.run()

