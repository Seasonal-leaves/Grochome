from flask import Flask

'''instantiating our app'''
app = Flask(__name__)

from app import models
from app import routes





