from flask import Flask, render_template, session, request, redirect, url_for, flash
#because request and requests are very close
import requests as httpRequests
import json

app = Flask(__name__)
app.secret_key = "this is another secret key"

@app.route("/", methods = ["GET"])
def status():
    if "name" not in session:
        return render_template("login.html")
    else:
        name = session["name"]
        secret = session["secret"]
        return render_template("status.html", name = name, secret = secret)

@app.route("/callback", methods = ["GET"])
def callback():
    status = request.args["request_status"]
    if (status == "granted"):
        r = request.args["authKey"]
        asktoken = httpRequests.get(
            "http://127.0.0.1:5000/oauth/token?authKey="
            + r
            + "&clientsecret=secretkeyclient"
        ).text
        asktoken = json.loads(asktoken)
        if (asktoken["response"] == "success"):
            userData = httpRequests.get(
                "http://127.0.0.1:5000/api/userdata?token="
                + asktoken["token"]
            ).text
            userData = json.loads(userData)
            session["name"] = userData["name"]
            session["secret"] = userData["secret"]
        return render_template("closingwindow.html")
    else:
        flash("Login was denied")
        return redirect(url_for("status"))

@app.route("/logout")
def logout():
    keys = []
    for key in session:
        keys.append(key)
    for key in keys:
        session.pop(key, None)
    return redirect(url_for("status"))

app.run(host = "127.0.0.2", port = 5000, debug = True)
