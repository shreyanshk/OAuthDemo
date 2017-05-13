from flask import Flask, Response

app = Flask(__name__)

@app.route("/")
def function():
    return "Client"

app.run(host = "127.0.0.1", port = 5000, debug = True)
