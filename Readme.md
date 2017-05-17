It is a simple and exploratory but complete implementation of OAuth. This repository include both an OAuth Identity provider and an OAuth Identity consumer who share user data via standard OAuth authorisation flow.

**This is not production quality code in any shape or form and is not expected to be used as such!**

Dependencies
------------
* Python 3
* Flask
* Flask-SQLAlchemy
* SQLAlchemy
* Requests

Install with pip:
>pip install -r requirements.txt

Starting Identity Provider
--------------------------
1. Open a terminal in the root/DemoServer directory of the project or, in other words, inside the DemoServer directory on directory where this file is located.
2. Execute command:
>python OAuthServer.py

Starting Identity Consumer
--------------------------
1. Open a terminal in the root/DemoClient directory of the project or, in other words, inside the DemoClient directory on directory where this file is located.
2. Execute command:
>python OAuthClient.py

Usage Documentation
-------------------
The default URLs are:
* Provider: [http://127.0.0.2:5000](http://127.0.0.2:5000)
* Consumer: [http://127.0.0.1:5000](http://127.0.0.1:5000)
