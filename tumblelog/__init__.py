from flask import Flask
from flask.ext.mongoengine import MongoEngine

app = Flask(__name__)

# configure MongoEngine and Flask
app.config['MONGODB_SETTINGS'] = {'DB': "my_tumble_log"}
app.config["SECRET_KEY"] = "A HUNGRY BROWN FOX JUMPED OVER A LAZY DOG."


db = MongoEngine(app)

if __name__ == '__main__':
    app.run()
