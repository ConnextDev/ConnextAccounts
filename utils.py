import os, sys, mariadb, json, random, string, requests, time, smtplib, threading, werkzeug
from flask import Flask, request, redirect, render_template, send_file, session, Markup
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

try: 
    conn = mariadb.connect(user="accounts", host="localhost", port=3306, database="accounts")

    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id bigint, name text, email text, password text, token text, permission int, recovery text, verified int, twofa int, secret text)")
    cursor.execute("CREATE TABLE IF NOT EXISTS user_apps (id bigint, app_id bigint, token text)")
    cursor.execute("CREATE TABLE IF NOT EXISTS apps (id bigint, owner_id bigint, callback text, permission int, name text, website text, approved int, verified int)")
    cursor.execute("CREATE TABLE IF NOT EXISTS reports (report_id bigint, report_title text, report_body text, email text)")
    conn.commit()
except mariadb.Error as e:
    print(f"Error connecting to MariaDB Platform: {e}")
    sys.exit(1)

vars = json.loads(open("vars.json").read())

smtp_url = vars["smtp_url"]
email_addr = vars["email_addr"]
email_pass = vars["email_pass"]
owner_secret = vars["owner_secret"]
session_secret = vars["session_secret"]
captcha_v3 = vars["captcha_v3"]
captcha_v2 = vars["captcha_v2"]

login_cache = []
ratelimit_cache = []
verify_cache = []

threads = []

def gen_id():
    return int("".join(random.choices(string.digits, k=16)))

def gen_token():
    return "".join(random.choices(string.ascii_letters + string.digits, k=256))

def gen_code():
    return "".join(random.choices(string.ascii_letters + string.digits, k=64))

def valid_string(string):
    if string == None or not type(string) == str:
        return False
    return len(string) > 0 and len(string) <= 512

def valid_int(integer):
    if integer == None:
        return False
    return type(integer) == int

def valid_id(id):
    if not valid_int(id):
        return False
    return len(str(id)) >= 15 and len(str(id)) <= 16

def valid_name(name):
    if not valid_string(name):
        return False
    return len(name) <= 32 and len(name) > 0

def valid_email(email):
    if not valid_string(email):
        return False
    return len(email) <= 64 and len(email) >= 5 and "+" not in email

def valid_password(password):
    if not valid_string(password):
        return False
    return len(password) <= 256 and len(password) >= 8

def valid_token(token):
    if not valid_string(token):
        return False
    return len(token) == 256

def valid_code(code):
    if not valid_string(code):
        return False
    return len(code) == 64

def verify_code_exists(verify_code):
    for verification in verify_cache:
        if verify_code == verification["code"]:
            return True
    return False

def email_send(email, subject, body):
    def email_wrapper(email, subject, body):
        with smtplib.SMTP(smtp_url, 587) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()

            smtp.login(email_addr, email_pass)

            msg = f"Subject: {subject}\n\n{body}"

            smtp.sendmail(email_addr, email, msg)
    email_thread = threading.Thread(target=email_wrapper, kwargs={"email": email, "subject": subject, "body": body})
    email_thread.start()
    return

class User:
    def __init__(self, id:int):
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (id,))
        data = cursor.fetchall()
        if not data:
            self.exists = False
        else:
            self.exists = True
            self.id = int(data[0][0])
            self.name = data[0][1]
            self.email = data[0][2]
            self.password_hash = data[0][3]
            self.token = data[0][4]
            self.permission = int(data[0][5])
            self.banned = self.permission < 2
            self.recovery = data[0][6]
            self.verified = bool(int(data[0][7]))
            self.twofa = bool(int(data[0][8]))
            self.secret = data[0][9]

    def apps(self):
        apps = []

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_apps WHERE id = ?", (self.id,))
        data = cursor.fetchall()
        for app in data:
            user_app = App(app[1])
            user_app.token = app[2]
            user_app.owned = False
            apps.append(user_app)

        cursor.execute("SELECT * FROM apps WHERE owner_id = ?", (self.id,))
        data = cursor.fetchall()
        for app in data:
            app = App(app[0])

            exists = False
            for user_app in apps:
                if app.id == user_app.id:
                    user_app.owned = True
                    exists = True
                    break
            if not exists:
                app.token = None
                app.owned = True
                apps.append(app)

        return apps

    def asdict(self, safe=True):
        if self.exists:
            if safe:
                return {"exists": int(self.exists), "id": self.id, "name": self.name}
            else:
                apps = []
                for app in self.apps():
                    app_dict = app.asdict()
                    app_dict["token"] = app.token
                    app_dict["owned"] = app.owned
                    apps.append(app_dict)
                return {"exists": int(self.exists), "id": self.id, "name": self.name, "email": self.email, "permission": self.permission, "banned": int(self.banned), "verified": int(self.verified), "apps": apps}
        else:
            return {"exists": int(self.exists)}

class User_Name(User):
    def __init__(self, name):
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE name = ?", (name,))
        data = cursor.fetchall()
        if not data:
            self.exists = False
        else:
            self.exists = True
            super().__init__(data[0][0])

class User_Email(User):
    def __init__(self, email):
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email.lower(),))
        data = cursor.fetchall()
        if not data:
            self.exists = False
        else:
            self.exists = True
            super().__init__(data[0][0])

class User_Token(User):
    def __init__(self, token):
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE token = ?", (token,))
        data = cursor.fetchall()
        if not data:
            self.exists = False
        else:
            self.exists = True
            super().__init__(data[0][0])

class User_Recovery(User):
    def __init__(self, recovery_code):
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE recovery = ?", (recovery_code,))
        data = cursor.fetchall()
        if not data:
            self.exists = False
        else:
            self.exists = True
            super().__init__(data[0][0])

class User_AppToken(User):
    def __init__(self, token):
        cursor = conn.cursor()
        cursor.execute("SELECT id, token FROM user_apps WHERE token = ?", (token,))
        data = cursor.fetchall()
        if not data:
            self.exists = False
        else:
            self.exists = True
            self.app = App(data[0][1])
            super().__init__(data[0][0])

User.Name = User_Name
User.Email = User_Email
User.Token = User_Token
User.Recovery = User_Recovery
User.AppToken = User_AppToken

class App:
    def __init__(self, id:int):
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM apps WHERE id = ?", (id,))
        data = cursor.fetchall()
        if not data:
            self.exists = False
        else:
            self.exists = True
            self.id = int(data[0][0])
            self.owner = User(data[0][1])
            self.callback = data[0][2]
            self.permission = int(data[0][3])
            self.name = data[0][4]
            self.website = data[0][5]
            self.approved = bool(int(data[0][6]))
            self.verified = bool(int(data[0][7]))

    def asdict(self):
        if self.exists:
            return {"exists": int(self.exists), "id": self.id, "owner": self.owner.asdict(), "callback": self.callback, "permission": self.permission, "name": self.name, "website": self.website, "approved": int(self.approved), "verified": int(self.verified)}
        else:
            return {"exists": int(self.exists)}

class App_Token(App):
    def __init__(self, token):
        cursor = conn.cursor()
        cursor.execute("SELECT id, token FROM user_apps WHERE token = ?", (token,))
        data = cursor.fetchall()
        if not data:
            self.exists = False
        else:
            self.exists = True
            self.user = User(data[0][0])
            super().__init__(data[0][1])

App.Token = App_Token

class IP:
    def __init__(self, address):
        if not address:
            self.address = "Unknown IP"
            self.location = "Unknown Location"
        else:
            self.address = address

            response = requests.get(f"http://ip-api.com/json/{self.address}")
            data = response.json()
            if not data.get("city") or not data.get("regionName"):
                self.location = "Unknown Location"
            else:
                self.location = data.get("city") + ", " + data.get("regionName")

def auth(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        token = request.headers.get("token")
        if not token: 
            return {"text": "Please specify a token!", "error": "no_token"}, 400
        account = User.Token(token)
        if not account.exists:
            return {"text": "Invalid token!", "error": "invalid_token"}, 401
        elif account.banned:
            return {"text": "Account is banned!", "error": "account_banned"}, 403
        elif not account.verified:
            return {"text": "Account is not verified!", "error": "account_unverified"}, 403

        return f(account, *args, **kwargs)
    return wrap

def ratelimit(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        ip = IP(request.headers.get("CF-Connecting-IP"))

        for user in ratelimit_cache:
            if ip.address == user["ip"]:
                if user["time"] > 0:
                    return {"text": "You are being ratelimited!", "error": "ratelimit"}, 429
                else:
                    user["time"] = 3
                    return f(*args, **kwargs)

        ratelimit_cache.append({"ip": ip.address, "time": 3})

        return f(*args, **kwargs)
    return wrap

def verify_expire():
    while 1:
        for verification in verify_cache:
            verification["expires"] -= 10
            if verification["expires"] < 10:
                verify_cache.remove(verification)
            time.sleep(10)

def ratelimit_expire():
    while 1:
        for user in ratelimit_cache:
            if user["time"] > 0:
                user["time"] -= 0.5
            time.sleep(0.5)

threads.append(threading.Thread(target=verify_expire))
threads.append(threading.Thread(target=ratelimit_expire))
for thread in threads:
    thread.start()