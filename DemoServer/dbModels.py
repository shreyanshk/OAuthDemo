from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import random
import string

dbctx = SQLAlchemy()

class User(dbctx.Model):
    __tablename__ = "Users"
    id = dbctx.Column(dbctx.Integer, primary_key = True)
    name = dbctx.Column(dbctx.String(50))
    passwd = dbctx.Column(dbctx.String(50))
    secret = dbctx.Column(dbctx.String(500))

    def __init__(self, name, passwd, secret = ""):
        self.name = name
        self.passwd = passwd
        self.secret = secret

class OAuthToken(dbctx.Model):
    __tablename__ = "OAuthTokens"
    id = dbctx.Column(dbctx.Integer, primary_key = True)
    authKey = dbctx.Column(dbctx.String(64))
    token = dbctx.Column(dbctx.String(64))
    rToken = dbctx.Column(dbctx.String(64))
    name = dbctx.Column(dbctx.String(64))
    scope = dbctx.Column(dbctx.String(10))
    cid = dbctx.Column(dbctx.String(15))
    exp = dbctx.Column(dbctx.DateTime)

    def __init__(self, authData, name):
        d = authData
        self.authKey = d["authKey"]
        self.name = name
        self.cid = d["cid"]
        self.scope = d["scope"]
        self.token = "tkn" + "".join(
            random.choices(
                string.ascii_uppercase + string.digits,
                k=61,
            )
        )
        self.rToken = "rtkn" + "".join(
            random.choices(
                string.ascii_uppercase + string.digits,
                k=60,
            )
        )
        self.exp = datetime.now() + timedelta(days = 1)
