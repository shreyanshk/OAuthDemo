from flask import Flask, render_template, session, redirect, url_for, request, abort, flash
from flask_sqlalchemy import SQLAlchemy
import json
import random
import string

app = Flask(__name__)

app.secret_key = "this is my secret key"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
#creating a temporary database in memory
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
app.jinja_env.auto_reload = True
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

dbctx = SQLAlchemy(app)

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
    rtoken = dbctx.Column(dbctx.String(64))
    name = dbctx.Column(dbctx.String(64))
    scope = dbctx.Column(dbctx.String(10))
    cid = dbctx.Column(dbctx.String(15))

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
        self.rtoken = "rtkn" + "".join(
            random.choices(
                string.ascii_uppercase + string.digits,
                k=60,
            )
        )

dbctx.create_all()

@app.route("/")
def status():
    if "name" in session:
        #display secret and button to logout
        return render_template("status.html",
            name = session["name"],
            secret = getSecret())
    else:
        return render_template("status.html")

@app.route("/oauth/authorize", methods = ["GET", "POST"])
def askUserAuth():
    if request.method == "GET":
        r = request.args
        try:
            authData = {
                "cid": r["cid"],
                "redirUrl": r["redirUrl"],
                "scope": r["scope"],
            }
            #for now only two scopes are assumed
            if (authData["scope"] != "read") and (authData["scope"] != "readwrite"):
                abort(400)
            session["authData"] = authData
        except KeyError:
            if "authData" in session:
                authData = session["authData"]
            else:
                abort(400)
        #hardcoded cid for checking
        if ("name" not in session) and (authData["cid"] == "OAuthDemoClient"):
            return redirect(url_for("login") + "?callback=/oauth/authorize")
        elif ("name" in session) and (authData["cid"] == "OAuthDemoClient"):
            #generate random key to protect from CSRF
            authKey = "".join(
                random.choices(
                    string.ascii_uppercase + string.digits,
                    k=64,
                )
            )
            authData = session["authData"]
            authData["authKey"] = authKey
            session["authData"] = authData
            return render_template("prompt.html",
                authData = session["authData"],
                name = session["name"],
            )
        else:
            abort(401)
    elif request.method == "POST":
        r = request.form
        #reusing authKey as csrf hidden key
        if (r["accept"] == "true") and (r["csrfprotect"] == session["authData"]["authKey"]):
            callback = session["authData"]["redirUrl"]
            callback = callback + "?request_status=granted&authKey=" + r["csrfprotect"]
            oauthtoken = OAuthToken(session["authData"], session["name"])
            dbctx.session.add(oauthtoken)
            dbctx.session.commit()
            session.pop("authData", None)
            return redirect(callback)
        elif r["accept"] == "false":
            callback = session["authData"]["redirUrl"]
            callback = callback + "?request_status=denied"
            session.pop("authData", None)
            return redirect(callback)
        elif (r[csrfprotect] != session["authData"]["authKey"]):
            abort(401)

@app.route("/oauth/token", methods = ["GET"])
def returnToken():
    r = request.args
    try:
        clientsecret = r["clientsecret"]
        authKey = r["authKey"]
    except KeyError:
        return json.dumps({
            "response": "invalid request"
        })
    if(clientsecret != "secretkeyclient"):
        return json.dumps({
            "response": "not authorized"
        })
    else:
        oauthtoken = OAuthToken.query.filter_by(authKey = authKey).first()
        if (oauthtoken == None):
            return json.dumps({
                "response": "not authorized"
            })
        else:
            token = oauthtoken.token
            return json.dumps({
                "response": "success",
                "token": token
            })

@app.route("/login", methods = ["GET", "POST"])
def login():
    if request.method == "GET":
        try:
            callback = request.args["callback"]
        except KeyError:
            callback = url_for("status")
        if "name" in session:
            return redirect(callback)
        elif "name" not in session:
            return render_template("login.html", callback = callback)
    elif request.method == "POST":
        r = request.form
        name, passwd = (r["name"], r["passwd"])
        callback = r["callback"]
        validUser = verifyUser(name, passwd)
        if validUser:
            session["name"] = name
            return redirect(callback)
        else:
            flash("Incorrect password.")
            return render_template("login.html", callback = callback)

def verifyUser(name, passwd):
        user = User.query.filter_by(name = name).first()
        if (user == None):
            return False
        else:
            dbpass = user.passwd
            if (dbpass == passwd):
                return True
            else:
                return False

def getSecret():
    user = User.query.filter_by(name = session["name"]).first()
    secret = user.secret
    return str(secret)

@app.route("/secret", methods = ["GET"])
def displaySecret():
    if "name" in session:
        return getSecret()
    else:
        return redirect(url_for(login))

@app.route("/api/userdata", methods = ["GET"])
def returnUserData():
    token = request.args["token"]
    record = OAuthToken.query.filter_by(token = token).first()
    if (record == None):
        return json.dumps({
            "response": "not authorized",
        })
    else:
        name = record.name
        secret = User.query.filter_by(name = name).first().secret
        return json.dumps({
            "response": "success",
            "name": name,
            "secret": secret,
        })


@app.route("/logout")
def logout():
    keys = []
    for key in session:
        keys.append(key)
    for key in keys:
        session.pop(key, None)
    return redirect(url_for("status"))

@app.route("/register", methods = ["GET", "POST"])
def register():
    if request.method == "GET":
        if "name" in session:
            return redirect(url_for("status"))
        return render_template("register.html")
    elif request.method == "POST":
        r = request.form
        name, passwd, secret = (r["name"], r["passwd"], r["secret"])
        #hash password for more security
        user = User(name, passwd, secret)
        dbctx.session.add(user)
        dbctx.session.commit()
        return "User " + name + " created."

app.run(host = "127.0.0.1", port = 5000, debug = True)
