"""
Management console for the app
"""

import os, sys, socket
from flask.ext.script import Manager
from app import api

# set the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
basedir = os.path.abspath(os.path.dirname(__file__))

manager = Manager(api)

if __name__ == "__main__":
    manager.run()


