#!/usr/bin/python3

from utils import *

# Global Variables

app = Flask(__name__, template_folder="./html")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SECRET_KEY"] = session_secret
ext = ["jpg", "png"]

# Rules

# Identification > Authorization [password] > Authorization [token/extra] > Details > Generation > Database
# Text > Info > Extra
# User provided > Preset value/Database provided # Database provided > Preset value

# Error Handler

@app.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return {"text": "Bad request!", "error": "bad_request"}, 400

@app.errorhandler(werkzeug.exceptions.InternalServerError)
def handle_server_error(e):
    return {"text": "Server error!", "error": "server_error"}, 500

@app.errorhandler(werkzeug.exceptions.RequestEntityTooLarge)
def handle_large_request(e):
    return {"text": "Request is too large!", "error": "large_request"}, 413

# Frontend

## File Handler

@app.route("/icon/<int:user_id>")
def icon_handler(user_id):
    return send_file(f"./icon/{secure_filename(user_id)}.png")

@app.route("/media/<string:file>")
def media_handler(file):
    return send_file(f"./media/{secure_filename(file)}")

## Templates

@app.route("/register")
def register():
    if session.get("code") in login_cache:
        return redirect("/account", 302)
    else:
        return render_template("register.html")

@app.route("/register/resend")
def register_resend():
    if session.get("code") in login_cache:
        return redirect("/account", 302)
    else:
        return render_template("register_resend.html")

@app.route("/verify")
def verify():
    if session.get("code") in login_cache:
        return redirect("/account", 302)
    else:
        return render_template("verify.html")

@app.route("/login")
def login():
    id = request.args.get("id")
    response_type = request.args.get("type")

    if session.get("code") in login_cache:
        if id and response_type:
            return redirect(f"/oauth/authorize?type={response_type}&id={id}", 302)
        else:
            return redirect("/account", 302)
    else:
        return render_template("login.html")

# API

# ban ratelimit
# complete moderation
# switch to elif

# overall stuff

# home page
# account page
# reset password
# change username
# change email
# change password
# change icon
# enable/disable 2fa
# reports
# app dashboard

## Register/Login

### Register

@app.route("/api/register", methods=["POST"])
@ratelimit
def api_register():
    json = request.json
    if not json:
        return {"text": "Bad request!", "error": "bad_request"}, 400

    name = str(json.get("name"))
    if not valid_name(name): 
        return {"text": "Invalid username!", "error": "invalid_username"}, 400
    if User.Name(name).exists:
        return {"text": "Username already exists!", "error": "username_exists"}, 403

    email = json.get("email")
    if not valid_email(email):
        return {"text": "Invalid email!", "error": "invalid_email"}, 400
    if User.Email(email).exists:
        return {"text": "Email already exists!", "error": "email_exists"}, 403
    email = email.lower()

    password = str(json.get("password"))
    if not valid_password(password):
        return {"text": "Invalid password!", "error": "invalid_password"}, 400

    captcha = json.get("captcha")
    if not valid_string(captcha):
        return {"text": "Invalid captcha response!", "error": "invalid_captcha_response"}, 400
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", data={"secret": captcha_v3, "response": captcha})
    data = response.json()
    if not data["success"]:
        return {"text": "Invalid captcha response!", "error": "invalid_captcha_response"}, 401

    id = gen_id()
    while User(id).exists:
        id = gen_id()

    token = gen_token()
    while User.Token(token).exists:
        token = gen_token()

    recovery_code = gen_code()
    while User.Recovery(recovery_code).exists:
        recovery_code = gen_code()

    cursor = conn.cursor()
    cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, 2, NULL, ?, 0, 0)", (id, name, email, generate_password_hash(password), token, recovery_code))
    conn.commit()

    os.system(f"cp ./media/logo.webp ./icon/{id}.webp")

    verify_code = gen_code()
    while verify_code_exists(verify_code):
        verify_code = gen_code()

    verify_cache.append({"id": id, "code": verify_code, "expires": 86400})

    subject = "Connext Email Verification"
    ip = IP(request.headers.get('CF-Connecting-IP'))
    body = f"Hello {name}!\n\nThanks for signing up with Connext! One quick thing, we need you to verify your account.\n\nGo to https://connext.dev/verify?code={verify_code} to verify your account.\nRegistered at {ip.location} by {ip.address}"
    email_send(email, subject, body)

    return {"text": "Account created.", "recovery_code": recovery_code}, 200

@app.route("/api/register/resend", methods=["POST"])
@ratelimit
def api_register_resend():
    json = request.json
    if not json:
        return {"text": "Bad request!", "error": "bad_request"}, 400

    code = json.get("code")
    if not valid_code(code):
        return {"text": "Invalid recovery code!", "error": "invalid_recovery_code"}, 400
    user = User.Recovery(code)
    if not user.exists:
        return {"text": "Recovery code doesn't exist!", "error": "recovery_code_not_exist"}, 404
    if user.banned:
        return {"text": "Account is banned!", "error": "account_banned"}, 403

    email = json.get("email")
    if not valid_email(email):
        return {"text": "Invalid email!", "error": "invalid_email"}, 400
    email_user = User.Email(email)
    if email_user.exists and user.id != email_user.id:
        return {"text": "Email already exists!", "error": "email_exists"}, 403
    email = email.lower()

    captcha = json.get("captcha")
    if not valid_string(captcha):
        return {"text": "Invalid captcha response!", "error": "invalid_captcha_response"}, 400
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", data={"secret": captcha_v3, "response": captcha})
    data = response.json()
    if not data["success"]:
        return {"text": "Invalid captcha response!", "error": "invalid_captcha_response"}, 401

    cursor = conn.cursor()
    cursor.execute("UPDATE users SET email = ? WHERE id = ?", (email, user.id))
    conn.commit()

    for verification in verify_cache:
        if user.id == verification["id"]:
            verify_cache.remove(verification)

    verify_code = gen_code()
    while verify_code_exists(verify_code):
        verify_code = gen_code()

    verify_cache.append({"id": user.id, "code": verify_code, "expires": 86400})

    subject = "Connext Email Verification"
    ip = IP(request.headers.get('CF-Connecting-IP'))
    body = f"Hello {user.name}!\n\nThanks for signing up with Connext! One quick thing, we need you to verify your account.\n\nGo to https://connext.dev/verify?code={verify_code} to verify your account.\nRegistered at {ip.location} by {ip.address}"
    email_send(email, subject, body)

    return {"text": "Email sent."}, 200

@app.route("/api/verify", methods=["POST"])
@ratelimit
def api_verify():
    json = request.json
    if not json:
        return {"text": "Bad request!", "error": "bad_request"}, 400

    code = json.get("code")
    if not code:
        return {"text": "Please verify your account!", "error": "account_unverified"}, 403
    elif not valid_code(code):
        return {"text": "Invalid verification code!", "error": "invalid_verify_code"}, 400

    captcha = json.get("captcha")
    if not valid_string(captcha):
        return {"text": "Invalid captcha response!", "error": "invalid_captcha_response"}, 400
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", data={"secret": captcha_v2, "response": captcha})
    data = response.json()
    if not data["success"]:
        return {"text": "Invalid captcha response!", "error": "invalid_captcha_response"}, 401

    for verification in verify_cache:
        if code == verification["code"]:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET verified = 1 WHERE id = ?", (verification["id"],))
            cursor.execute("UPDATE users SET recovery = NULL WHERE id = ?", (verification["id"],))
            conn.commit()

            return {"text": "Verified account."}, 200

    return {"text": f"Verification code doesn't exist! Please request a new email from <a href='https://connext.dev/register/resend'>https://connext.dev/register/resend</a>.", "error": "verify_code_not_exist"}, 404

### Login

@app.route("/api/login", methods=["POST"])
@ratelimit
def api_login():
    json = request.json
    if not json:
        return {"text": "Bad request!", "error": "bad_request"}, 400

    email = json.get("email")
    if not valid_email(email):
        return {"text": "Invalid email!", "error": "invalid_email"}, 400
    account = User.Email(email)
    if not account.exists:
        return {"text": "Email doesn't exist!", "error": "email_not_exist"}, 404
    if account.banned:
        return {"text": "Account is banned!", "error": "account_banned"}, 403
    email = email.lower()

    password = str(json.get("password"))
    if not valid_password(password):
        return {"text": "Invalid password!", "error": "invalid_password"}, 400

    captcha = json.get("captcha")
    if not valid_string(captcha):
        return {"text": "Invalid captcha response!", "error": "invalid_captcha_response"}, 400
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", data={"secret": captcha_v3, "response": captcha})
    data = response.json()
    if not data["success"]:
        return {"text": "Invalid captcha response!", "error": "invalid_captcha_response"}, 401

    if check_password_hash(account.password_hash, password):
        if not account.verified:
            return {"text": "Please verify your account!", "error": "account_unverified"}, 403

        subject = "New Login"
        ip = IP(request.headers.get('CF-Connecting-IP'))
        body = f"Hello {account.name}!\n\nThere has been a new login to your account!\n\nIf this was not you, reset your password immediately and enable 2FA if possible. Logged in at {ip.location} by {ip.address}"
        email_send(email, subject, body)

        login_code = gen_code()
        session["code"] = login_code
        login_cache.append(login_code)

        return {"text": "Logged in.", "token": account.token}, 200
    else: 
        return {"text": "Incorrect password!", "error": "incorrect_password"}, 401

@app.route("/api/login/code")
@auth
def api_login_code(account):
    if not session.get("code") in login_cache:
        login_code = gen_code()
        session["code"] = login_code
        login_cache.append(login_code)

    return {"text": "Registered login code."}, 200

## User Info

@app.route("/api/account")
@auth
def api_account(account):
    return account.asdict(False), 200

@app.route("/api/users/<int:id>")
def api_users_id(id):
    if not valid_id(id):
        return {"text": "Invalid user ID!", "error": "invalid_user_id"}, 400
    user = User(id)
    if not user.exists:
        return {"text": "User doesn't exist!", "error": "user_not_exist"}, 404

    return user.asdict(), 200

## OAuth

@app.route("/oauth/authorize")
def oauth_authorize():
    args = request.args
    if args is None:
        return {"text": "Bad request!", "error": "bad_request"}, 400

    response_type = args.get("type")
    if response_type == "token":
        id = args.get("id")
        try:
            if not valid_id(int(id)):
                return {"text": "Invalid app ID!", "error": "invalid_app_id"}, 400
        except ValueError:
            return {"text": "Invalid app ID!", "error": "invalid_app_id"}, 400
        app = App(id)
        if not app.exists:
            return {"text": "App doesn't exist!", "error": "app_not_exist"}, 404
        if not app.approved:
            return {"text": "App isn't approved!", "error": "app_unapproved"}, 403

        return render_template("oauth_authorize.html", id=app.id, name=app.name, owner=app.owner.name, callback=app.callback, permission=app.permission, website=app.website, verified=app.verified)
    else:
        return {"text": "Response type not supported!", "error": "invalid_response_type"}, 400

@app.route("/oauth/register", methods=["POST"])
@auth
def oauth_register(account):
    json = request.json
    if not json:
        return {"text": "Bad request!", "error": "bad_request"}, 400

    response_type = json.get("type")
    if response_type == "token":
        id = json.get("id")
        if not valid_id(id):
            return {"text": "Invalid app ID!", "error": "invalid_app_id"}, 400
        app = App(id)
        if not app.exists:
            return {"text": "App doesn't exist!", "error": "app_not_exist"}, 404
        if not app.approved:
            return {"text": "App isn't approved!", "error": "app_unapproved"}, 403

        captcha = json.get("captcha")
        if not valid_string(captcha):
            return {"text": "Invalid captcha response!", "error": "invalid_captcha_response"}, 400
        response = requests.post("https://www.google.com/recaptcha/api/siteverify", data={"secret": captcha_v3, "response": captcha})
        data = response.json()
        if not data["success"]:
            return {"text": "Invalid captcha response!", "error": "invalid_captcha_response"}, 401

        for app in account.apps():
            if id == app.id and app.token:
                return {"text": "Token granted.", "token": app.token}, 200

        token = gen_code()
        while App.Token(token).exists:
            token = gen_code()

        cursor = conn.cursor()
        cursor.execute("INSERT INTO user_apps VALUES (?, ?, ?)", (account.id, app.id, token))
        conn.commit()

        return {"text": "Token created.", "token": token}, 200
    else:
        return {"text": "Response type not supported!", "error": "invalid_response_type"}, 400

@app.route("/oauth/user")
def oauth_user(id):
    args = request.args
    if not args:
        return {"text": "Bad request!", "error": "bad_request"}, 400

    token = args.get("token")
    if not valid_code(token): 
        return {"text": "Invalid app token!", "error": "invalid_app_token"}, 400
    user = User.AppToken(token)
    if not user.exists:
        return {"text": "User doesn't exist!", "error": "user_not_exist"}, 404
    if user.banned:
        return {"text": "User is banned!", "error": "user_banned"}, 403
    if not user.verified:
        return {"text": "User is not verified!", "error": "user_unverified"}, 403

    app = user.app
    if not app.approved:
        return {"text": "App isn't approved!", "error": "app_unapproved"}, 403

    response_json = {"id": user.id, "name": user.name}
    
    if app.permission == 2:
        response_json["email"] = user.email

    return response_json, 200

## Developer

@app.route("/api/apps/create", methods=["POST"])
@ratelimit
@auth
def api_apps_create(account):
    json = request.json
    if not json:
        return {"text": "Bad request!", "error": "bad_request"}, 400

    callback = json.get("callback")
    if not valid_string(callback):
        return {"text": "Invalid callback!", "error": "invalid_callback"}, 400

    permission = json.get("permission")
    if not valid_int(permission):
        return {"text": "Invalid permissions!", "error": "invalid_permission"}, 400
    if permission < 1 or permission > 2:
        return {"text": "Invalid permissions!", "error": "invalid_permission"}, 400

    name = json.get("name")
    if not valid_name(name):
        return {"text": "Invalid name!", "error": "invalid_name"}, 400

    website = json.get("website")
    if not valid_string(website):
        return {"text": "Invalid website!", "error": "invalid_website"}, 400

    id = gen_id()
    while App(id).exists:
        id = gen_id()

    cursor = conn.cursor()
    cursor.execute("INSERT INTO apps VALUES (?, ?, ?, ?, ?, ?, 0, 0)", (id, account.id, callback, permission, name, website))
    conn.commit()

    return {"text": "App created.", "id": id}, 200

@app.route("/api/apps/<int:id>/update", methods=["POST"])
@ratelimit
@auth
def api_apps_update(account, id):
    json = request.json
    if not json:
        return {"text": "Bad request!", "error": "bad_request"}, 400

    if not valid_id(id):
        return {"text": "Invalid app ID!", "error": "invalid_app_id"}, 400
    app = App(id)
    if not app.exists:
        return {"text": "App doesn't exist!", "error": "app_not_exist"}, 404
    if account.id != app.owner.id:
        return {"text": "You do not own this app!", "error": "no_app_access"}, 403

    cursor = conn.cursor()

    callback = json.get("callback")
    if valid_string(callback):
        cursor.execute("UPDATE apps SET callback = ? WHERE id = ?", (callback, id))

    permission = json.get("permission")
    if valid_int(permission):
        cursor.execute("UPDATE apps SET permission = ? WHERE id = ?", (permission, id))
    if permission < 1 or permission > 2:
        return {"text": "Invalid permissions!", "error": "invalid_permission"}, 400

    name = json.get("name")
    if valid_name(name):
        cursor.execute("UPDATE apps SET name = ? WHERE id = ?", (name, id))

    website = json.get("website")
    if valid_string(website):
        cursor.execute("UPDATE apps SET website = ? WHERE id = ?", (website, id))

    cursor.execute("UPDATE apps SET approved = 0 WHERE id = ?", (id,))
    conn.commit()

    return {"text": "App updated."}, 200

@app.route("/api/apps/<int:id>/delete", methods=["POST"])
@ratelimit
@auth
def api_apps_delete(account, id):
    if not valid_id(id):
        return {"text": "Invalid app ID!", "error": "invalid_app_id"}, 400
    app = App(id)
    if not app.exists:
        return {"text": "App doesn't exist!", "error": "app_not_exist"}, 404
    if account.id != app.owner.id:
        return {"text": "You do not own this app!", "error": "no_app_access"}, 403

    cursor = conn.cursor()
    cursor.execute("DELETE FROM user_apps WHERE app_id = ?", (id,))
    cursor.execute("DELETE FROM apps WHERE id = ?", (id,))
    conn.commit()

    return {"text": "App deleted."}, 200

@app.route("/api/apps/<int:id>/approve", methods=["POST"])
@auth
def api_apps_approve(account, id):
    if account.permission < 4:
        return {"text": "Insufficient permissions!"}, 403

    if not valid_id(id):
        return {"text": "Invalid app ID!", "error": "invalid_app_id"}, 400
    app = App(id)
    if not app.exists:
        return {"text": "App doesn't exist!", "error": "app_not_exist"}, 404

    cursor = conn.cursor()
    cursor.execute("UPDATE apps SET approved = 1 WHERE id = ?", (id,))
    conn.commit()

    return {"text": "App approved."}, 200

@app.route("/api/apps/<int:id>/verify", methods=["POST"])
@auth
def api_apps_verify(account, id):
    if account.permission < 4:
        return {"text": "Insufficient permissions!"}, 403

    if not valid_id(id):
        return {"text": "Invalid app ID!", "error": "invalid_app_id"}, 400
    app = App(id)
    if not app.exists:
        return {"text": "App doesn't exist!", "error": "app_not_exist"}, 404

    cursor = conn.cursor()
    cursor.execute("UPDATE apps SET verified = 1 WHERE id = ?", (id,))
    conn.commit()

    return {"text": "App verified."}, 200

## Admin

@app.route("/api/users/<int:id>/set/owner", methods=["POST"])
def api_set_owner(id):
    json = request.json
    if not json:
        return {"text": "Bad request!", "error": "bad_request"}, 400

    code = json.get("code")
    if not valid_code(code):
        return {"text": "Invalid owner code!", "error": "invalid_owner_code"}, 400
    if code != owner_secret:
        return {"text": "Incorrect owner code!", "error": "incorrect_owner_code"}, 401

    if not valid_id(id): 
        return {"text": "Invalid user ID!", "error": "invalid_user_id"}, 400
    user = User(id)
    if not user.exists:
        return {"text": "User doesn't exist!", "error": "user_not_exist"}, 404
    if not user.verified:
        return {"text": "User is not verified!", "error": "user_unverified"}, 403

    cursor = conn.cursor()
    cursor.execute("UPDATE users SET permission = 5 WHERE id = ?", (user.id,))
    conn.commit()

    return {"text": f"Gave {user.name} owner access."}, 200

if __name__ == "__main__":
    app.run()