#! ../flask/bin/python
import unittest

from app import api, db
from app.models import User

class TestCase(unittest.TestCase):

    def setUp(self):
        api.config["TESTING"] = True
        api.config["MONGODB_SETTINGS"] = {'DB': 'unittest_db'}
        assert db is not None

    def tearDown(self):
        User.objects(username__startswith="testingObject").delete()

    def test_createUser(self):
        u = User(username='testingObject1')
        u.save()
        u.password_hash = u.hash_password('testing')
        # Testing user creation
        createduser = User.objects(username='testingObject1').first()
        assert createduser is not None
        # validating password hash.
        assert createduser.password_hash == u.hash_password('testing')
        assert u.verify_password('testing')

    def test_validateTokens(self):
        u = User(username='testingObject2')
        u.save()
        authToken = u.generate_auth_token()
        resetToken = u.generate_reset_token()
        assert User.verify_auth_token(authToken) is not None
        assert User.verify_auth_token(resetToken) is None
        assert User.verify_reset_token(authToken) is None
        assert User.verify_reset_token(resetToken) is not None

if __name__ == "__main__":
    unittest.main()
