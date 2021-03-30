#!/usr/bin/python3

from utils import (os, werkzeug, jwt, time, re,

                   request, redirect, render_template, send_file, session,
                   Markup, secure_filename, escape,

                   generate_password_hash, check_password_hash,

                   smtp_url, email_addr, email_pass, owner_secret,
                   session_secret, captcha_v3, captcha_v2,

                   ratelimit_cache, register_cache, verify_cache,

                   flask, db, exts,

                   User, App, AppUser, IP,

                   email_send, gen_id, gen_token, json_key, args_key,
                   user_asdict, app_asdict, session_key, captcha2, captcha3,
                   auth, no_auth, ratelimit)


# Error Handler


@flask.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return {"text": "Bad request!",
            "error": "bad_request"}, 400


@flask.errorhandler(werkzeug.exceptions.Unauthorized)
def handle_unauthorized(e):
    return {"text": "Unauthorized!",
            "error": "unauthorized"}, 401


@flask.errorhandler(werkzeug.exceptions.Forbidden)
def handle_forbidden(e):
    return render_template("forbidden.html", error=""), 403


@flask.errorhandler(werkzeug.exceptions.NotFound)
def handle_not_found(e):
    return render_template("not_found.html", error=""), 404


@flask.errorhandler(werkzeug.exceptions.MethodNotAllowed)
def handle_bad_method(e):
    return {"text": "Method not allowed!",
            "error": "method_unallowed"}, 405


@flask.errorhandler(werkzeug.exceptions.RequestTimeout)
def handle_timeout(e):
    return {"text": "Request timed out!",
            "error": "timeout"}, 405


@flask.errorhandler(werkzeug.exceptions.RequestEntityTooLarge)
def handle_large_request(e):
    return {"text": "Request is too large!",
            "error": "large_request"}, 413


@flask.errorhandler(werkzeug.exceptions.TooManyRequests)
def handle_ratelimit(e):
    return {"text": "You are being ratelimited!",
            "error": "ratelimit"}, 429


@flask.errorhandler(werkzeug.exceptions.InternalServerError)
def handle_server_error(e):
    return {"text": "Server error!",
            "error": "server_error"}, 500


# Frontend

# File Handler


@flask.route("/icon/<int:user_id>")
def icon_handler(user_id):
    return send_file(f"./icon/{secure_filename(user_id)}.png")


@flask.route("/media/<string:file>")
def media_handler(file):
    return send_file(f"./media/{secure_filename(file)}")


# Templates


@flask.route("/")
def html_index():
    return render_template("unfinished.html"), 404


@flask.route("/account")
@auth(True, "/login")
def html_account(account):
    return render_template("unfinished.html"), 404


@flask.route("/developer")
@auth(True, "/login", "developer")
def html_developer(account):
    return render_template("unfinished.html"), 404


@flask.route("/moderator")
@auth(True, "/login", "moderator")
def html_moderator(account):
    if not account.permission >= 1:
        return render_template("forbidden.html",
                               error="You are not a moderator!"), 403

    return render_template("unfinished.html"), 404


@flask.route("/admin")
@auth(True, "/login", "admin")
def html_admin(account):
    if not account.permission >= 2:
        return render_template("forbidden.html",
                               error="You are not an admin!"), 403

    return render_template("unfinished.html"), 404


@flask.route("/register")
@no_auth("/account")
def html_register():
    return render_template("register.html")


@flask.route("/register/resend")
@no_auth("/account")
def html_register_resend():
    return render_template("register_resend.html")


@flask.route("/verify")
@no_auth("/account")
def html_verify():
    return render_template("verify.html")


@flask.route("/login")
@no_auth("/account")
def html_login():
    return render_template("login.html")


@flask.route("/delete")
def html_delete():
    return render_template("delete.html")


@flask.route("/error")
@args_key("code", required=False)
def html_error(code):
    if code == "account_banned":
        error = "Account is banned!"
    elif code == "account_unverified":
        error = "Account is not verified!"
    elif code == "government_secret":
        error = ("This page is hiding a government secret! "
                 "I'm pretty sure aliens don't exist, pretty sure...")
    else:
        error = "There was an error! That's all we know."

    return render_template("error.html", error=error)


@flask.route("/403")
def html_forbidden():
    return render_template("forbidden.html",
                           error="Be proud of yourself, "
                                 + "you did nothing wrong!"), 403


@flask.route("/404")
def html_not_found():
    return render_template("not_found.html",
                           error="Be proud of yourself, "
                                 + "you did nothing wrong!"), 404


# API

# Register/Login

# Register


@flask.route("/api/register", methods=["POST"])
@ratelimit
@no_auth()
@captcha3
@json_key("name", 1, 32)
@json_key("email", 1, 64)
@json_key("password", 8, 256)
def api_register(name, email, password):
    ip = IP(request.headers.get('CF-Connecting-IP'))

    for user in register_cache:
        if ip.address == user["ip"]:
            return {"text": "You are being ratelimited!",
                    "error": "ratelimit"}, 429

    if not re.search(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                     email):

        return {"text": "Invalid email!", "error": "invalid_email"}, 400

    if User.query.filter_by(name=name).first():
        return {"text": "Username already exists!",
                "error": "username_exists"}, 403

    elif User.query.filter(db.func.lower(User.email)
                           == db.func.lower(email)).first():

        return {"text": "Email already exists!",
                "error": "email_exists"}, 403

    id = gen_id(1, User, "id")
    recovery_token = gen_token(User, "recovery_token")
    token_secret = gen_token(User, "token_secret")

    token = jwt.encode({"id": id,
                        "name": name,
                        "permission": 0,
                        "verified": False,
                        "banned": False},
                       token_secret,
                       algorithm="HS256")

    db.session.add(User(id=id,
                        name=name,
                        email=email,
                        password=generate_password_hash(password),
                        token=token,
                        token_secret=token_secret,
                        recovery_token=recovery_token,
                        permission=0,
                        verified=False,
                        banned=False))

    db.session.commit()

    os.system(f"cp ./media/logo.webp ./icon/{id}.webp")

    verify_token = gen_token()
    verify_cache.append({"id": id,
                         "verify_token": verify_token,
                         "expires": 86400})

    subject = "Connext Email Verification"
    body = (f"Hello {escape(name)}!\n\n"
            "Thanks for signing up with Connext! "
            "One quick thing, we need you to verify your account.\n\n"
            f"Go to https://connext.dev/verify#token={verify_token} "
            "to verify your account.\n\n"
            f"Registered at {ip.location} by {ip.address}")

    email_send(email, subject, body)

    register_cache.append({"ip": ip.address, "time": 10800})

    session["recovery_token"] = recovery_token

    return {"text": f"Account '{name}' created.",
            "account": user_asdict(User.query.filter_by(id=id).first())}, 200


@flask.route("/api/register/resend", methods=["POST"])
@ratelimit
@no_auth()
@captcha3
@session_key("recovery_token", 256, 256)
@json_key("email", 1, 64)
def api_register_resend(recovery_token, email):
    account = User.query.filter_by(recovery_token=recovery_token).first()
    if not account:
        return {"text": "Recovery token does not exist!",
                "error": "invalid_recovery_token"}, 401

    elif account.banned:
        return {"text": "Account is banned!",
                "error": "account_banned"}, 403

    if not re.search(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                     email):

        return {"text": "Invalid email!", "error": "invalid_email"}, 400

    email_account = User.query.filter(db.func.lower(User.email)
                                      == db.func.lower(email)).first()

    if email_account and account.id != email_account.id:
        return {"text": "Email already exists!",
                "error": "email_exists"}, 403

    account.email = email

    db.session.commit()

    for verification in verify_cache:
        if account.id == verification["id"]:
            verify_cache.remove(verification)

    verify_token = gen_token()
    verify_cache.append({"id": account.id,
                         "verify_token": verify_token,
                         "expires": 86400})

    subject = "Connext Email Verification"
    ip = IP(request.headers.get('CF-Connecting-IP'))
    body = (f"Hello {escape(account.name)}!\n\n"
            "Thanks for signing up with Connext! "
            "One quick thing, we need you to verify your account.\n\n"
            f"Go to https://connext.dev/verify#token={verify_token} "
            "to verify your account.\n\n"
            f"Registered at {ip.location} by {ip.address}")

    email_send(email, subject, body)

    return {"text": f"Email sent to '{email}'.",
            "account": user_asdict(account)}, 200


@flask.route("/api/verify", methods=["POST"])
@ratelimit
@no_auth()
@captcha2
@json_key("verify_token", 256, 256)
def api_verify(verify_token):
    for verification in verify_cache:
        print(verification)
        if verify_token == verification["verify_token"]:
            account = User.query.filter_by(id=verification["id"]).first()
            account.recovery_token = None
            account.verified = True
            account.token = jwt.encode(user_asdict(account),
                                       account.token_secret,
                                       algorithm="HS256")

            db.session.commit()

            session.pop("recovery_token")

            return {"text": f"Verified account for '{account.name}'.",
                    "account": user_asdict(account)}, 200

    return {"text": ("Verification token does not exist! "
                     "Please request a new email from "
                     "<a href='https://connext.dev/register/resend'>"
                     "https://connext.dev/register/resend</a>."),
            "error": "invalid_verify_token"}, 404


# Login


@flask.route("/api/login", methods=["POST"])
@ratelimit
@no_auth()
# @captcha3
@json_key("email", 1, 64)
@json_key("password", 8, 256)
def api_login(email, password):
    if not re.search(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                     email):

        return {"text": "Invalid email!", "error": "invalid_email"}, 400

    account = User.query.filter(db.func.lower(User.email)
                                == db.func.lower(email)).first()

    if not account:
        return {"text": "Email does not exist!",
                "error": "invalid_email"}, 404

    elif account.banned:
        return {"text": "Account is banned!",
                "error": "account_banned"}, 403

    elif not account.verified:
        return {"text": "Please verify your account!",
                "error": "account_unverified"}, 403

    if check_password_hash(account.password, password):
        subject = "New Login"
        ip = IP(request.headers.get('CF-Connecting-IP'))
        body = (f"Hello {escape(account.name)}!\n\n"
                "There has been a new login to your account!\n\n"
                "If this was not you, reset your password immediately and "
                "enable 2FA if possible.\n\n"
                f"Logged in at {ip.location} by {ip.address}")

        email_send(email, subject, body)

        session["token"] = account.token

        return {"text": f"Logged in as '{account.name}'.",
                "account": user_asdict(account)}, 200

    else:
        return {"text": "Incorrect password!",
                "error": "incorrect_password"}, 401


@flask.route("/logout")
@args_key("redirect_url")
def logout(redirect_url):
    try:
        session.pop("token")
        session.pop("recovery_token")
    except KeyError:
        pass

    if redirect_url:
        return redirect("/" + redirect_url, 302)
    else:
        return redirect("/", 302)


# User

# Info


@flask.route("/api/account")
@auth(True, "/login", "api/account")
def api_account(account):
    return user_asdict(account, True), 200


@flask.route("/api/users/<int:id>")
@auth(False)
def api_users_id(account, id):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    user = User.query.filter_by(id=id).first()
    if not user:
        return {"text": "User does not exist!",
                "error": "invalid_user_id"}, 404

    elif user.banned:
        return {"text": "User is banned!", "error": "user_banned"}, 403
    elif not user.verified:
        return {"text": "User is not verified!",
                "error": "user_unverified"}, 403

    return user_asdict(user), 200


# Admin


@flask.route("/api/users")
@auth(True, "/login", "api/users")
def api_users(account):
    if not account.permission >= 2:
        return {"text": "You are not an admin!",
                "error": "requires_admin"}, 403

    users = []
    for user in User.query.all():
        users.append(user_asdict(user))

    return {"users": users}


@flask.route("/api/users/<int:id>/set/owner", methods=["POST"])
@ratelimit
# @captcha3
@json_key("owner_token", 256, 256)
def api_set_owner(id, owner_token):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if owner_token != owner_secret:
        return {"text": "Incorrect owner token!",
                "error": "incorrect_owner_token"}, 401

    user = User.query.filter_by(id=id).first()
    if not user:
        return {"text": "User does not exist!",
                "error": "invalid_user_id"}, 404

    elif user.banned:
        return {"text": "User is banned!", "error": "user_banned"}, 403
    elif not user.verified:
        return {"text": "User is not verified!",
                "error": "user_unverified"}, 403

    user.permission = 3
    user.token = jwt.encode(user_asdict(user),
                            user.token_secret,
                            algorithm="HS256")

    for app_user in AppUser.query.filter_by(id=user.id).all():
        app_user.token = jwt.encode(user_asdict(user),
                                    app_user.app.secret,
                                    algorithm="HS256")

    db.session.commit()

    return {"text": f"Gave '{user.name}' owner access.",
            "user": user_asdict(user)}, 200


@flask.route("/api/users/<int:id>/set/admin", methods=["POST"])
@ratelimit
@auth(True)
# @captcha3
def api_set_admin(account, id):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if not account.permission == 3:
        return {"text": "You are not an owner!",
                "error": "requires_owner"}, 403

    user = User.query.filter_by(id=id).first()
    if not user:
        return {"text": "User does not exist!",
                "error": "invalid_user_id"}, 404

    elif user.banned:
        return {"text": "User is banned!", "error": "user_banned"}, 403
    elif not user.verified:
        return {"text": "User is not verified!",
                "error": "user_unverified"}, 403

    elif user.permission == 3:
        return {"text": "User has higher permissions/is an owner!",
                "error": "insufficient_permissions"}, 403

    user.permission = 2
    user.token = jwt.encode(user_asdict(user),
                            user.token_secret,
                            algorithm="HS256")

    for app_user in AppUser.query.filter_by(id=user.id).all():
        app_user.token = jwt.encode(user_asdict(user),
                                    app_user.app.secret,
                                    algorithm="HS256")

    db.session.commit()

    return {"text": f"Gave '{user.name}' administrator access.",
            "user": user_asdict(user)}, 200


@flask.route("/api/users/<int:id>/set/mod", methods=["POST"])
@ratelimit
@auth(True)
# @captcha3
def api_set_mod(account, id):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if not account.permission >= 2:
        return {"text": "You are not an administrator!",
                "error": "requires_admin"}, 403

    user = User.query.filter_by(id=id).first()
    if not user:
        return {"text": "User does not exist!",
                "error": "invalid_user_id"}, 404

    elif user.banned:
        return {"text": "User is banned!", "error": "user_banned"}, 403
    elif not user.verified:
        return {"text": "User is not verified!",
                "error": "user_unverified"}, 403

    elif ((user.permission == 2 and account.permission == 2) or
          user.permission == 3):

        return {"text": "User has higher permissions/is an owner!",
                "error": "insufficient_permissions"}, 403

    user.permission = 1
    user.token = jwt.encode(user_asdict(user),
                            user.token_secret,
                            algorithm="HS256")

    for app_user in AppUser.query.filter_by(id=user.id).all():
        app_user.token = jwt.encode(user_asdict(user),
                                    app_user.app.secret,
                                    algorithm="HS256")

    db.session.commit()

    return {"text": f"Gave '{user.name}' moderator access.",
            "user": user_asdict(user)}, 200


@flask.route("/api/users/<int:id>/set/user", methods=["POST"])
@ratelimit
@auth(True)
# @captcha3
def api_set_user(account, id):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if not account.permission >= 2:
        return {"text": "You are not an administrator!",
                "error": "requires_admin"}, 403

    user = User.query.filter_by(id=id).first()
    if not user:
        return {"text": "User does not exist!",
                "error": "invalid_user_id"}, 404

    elif not user.verified:
        return {"text": "User is not verified!",
                "error": "user_unverified"}, 403

    elif ((user.permission == 2 and account.permission < 3) or
          user.permission == 3):

        return {"text": "User has higher permissions/is an owner!",
                "error": "insufficient_permissions"}, 403

    user.permission = 0
    user.token = jwt.encode(user_asdict(user),
                            user.token_secret,
                            algorithm="HS256")

    for app_user in AppUser.query.filter_by(id=user.id).all():
        app_user.token = jwt.encode(user_asdict(user),
                                    app_user.app.secret,
                                    algorithm="HS256")

    db.session.commit()

    return {"text": f"Gave '{user.name}' user access.",
            "user": user_asdict(user)}, 200


@flask.route("/api/users/<int:id>/temp/ban", methods=["POST"])
@ratelimit
@auth(True)
# @captcha3
@json_key("reason", 1, 200)
def api_temp_ban(account, id, reason):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if not account.permission >= 1:
        return {"text": "You are not a moderator!",
                "error": "requires_mod"}, 403

    user = User.query.filter_by(id=id).first()
    if not user:
        return {"text": "User does not exist!",
                "error": "invalid_user_id"}, 404

    elif not user.verified:
        return {"text": "User is not verified!",
                "error": "user_unverified"}, 403

    elif ((user.permission == 2 and account.permission < 3) or
          (user.permission == 1 and account.permission < 2) or
          user.permission == 3):

        return {"text": "User has higher permissions/is an owner!",
                "error": "insufficient_permissions"}, 403

    user.banned = True
    user.ban_expiry = time.localtime(time.time() + 1209600)
    user.ban_reason = reason
    user.token = jwt.encode(user_asdict(user),
                            user.token_secret,
                            algorithm="HS256")

    for app_user in AppUser.query.filter_by(id=user.id).all():
        app_user.token = jwt.encode(user_asdict(user),
                                    app_user.app.secret,
                                    algorithm="HS256")

    for app in AppUser.query.filter_by(owner_id=user.id).all():
        app.approved = False
        app.verified = False

    db.session.commit()

    subject = "Ban Notice"
    body = (f"Hello {escape(account.name)}!\n\n"
            "A moderator has temporarily banned your account for 14 days. "
            "If you disagree with this, please contact another moderator.\n\n"
            f"You were banned with reason {user.ban_reason}\n\n"
            "We hope you understand. Thanks for using Connext!")

    email_send(user.email, subject, body)

    return {"text": (f"Temporarily banned '{user.name}' "
                     f"with reason '{reason}'."),
            "user": user_asdict(user)}, 200


@flask.route("/api/users/<int:id>/ban", methods=["POST"])
@ratelimit
@auth(True)
# @captcha3
@json_key("reason", 1, 200)
def api_ban(account, id, reason):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if not account.permission >= 1:
        return {"text": "You are not a moderator!",
                "error": "requires_mod"}, 403

    user = User.query.filter_by(id=id).first()
    if not user:
        return {"text": "User does not exist!",
                "error": "invalid_user_id"}, 404

    elif not user.verified:
        return {"text": "User is not verified!",
                "error": "user_unverified"}, 403

    elif ((user.permission == 2 and account.permission < 3) or
          (user.permission == 1 and account.permission < 2) or
          user.permission == 3):

        return {"text": "User has higher permissions/is an owner!",
                "error": "insufficient_permissions"}, 403

    user.banned = True
    user.ban_expiry = 0
    user.ban_reason = reason
    user.token = jwt.encode(user_asdict(user),
                            user.token_secret,
                            algorithm="HS256")

    for app_user in AppUser.query.filter_by(id=user.id).all():
        app_user.token = jwt.encode(user_asdict(user),
                                    app_user.app.secret,
                                    algorithm="HS256")

    for app in AppUser.query.filter_by(owner_id=user.id).all():
        app.approved = False
        app.verified = False

    db.session.commit()

    subject = "Ban Notice"
    body = (f"Hello {escape(account.name)}!\n\n"
            "A moderator has permanently banned your account. "
            "If you disagree with this, please contact another moderator.\n\n"
            f"You were banned with reason {user.ban_reason}\n\n"
            "If you'd like your account deleted, "
            "go to https://connext.dev/delete for instructions\n\n"
            "We hope you understand. Thanks for using Connext!")

    email_send(user.email, subject, body)

    return {"text": (f"Banned '{user.name}' "
                     f"with reason '{reason}'."),
            "user": user_asdict(user)}, 200


@flask.route("/api/users/<int:id>/unban", methods=["POST"])
@ratelimit
@auth(True)
# @captcha3
def api_unban(account, id):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if not account.permission >= 2:
        return {"text": "You are not an administrator!",
                "error": "requires_admin"}, 403

    user = User.query.filter_by(id=id).first()
    if not user:
        return {"text": "User does not exist!",
                "error": "invalid_user_id"}, 404

    elif not user.verified:
        return {"text": "User is not verified!",
                "error": "user_unverified"}, 403

    elif ((user.permission == 2 and account.permission < 3) or
          user.permission == 3):

        return {"text": "User has higher permissions/is an owner!",
                "error": "insufficient_permissions"}, 403

    user.banned = False
    user.ban_expiry = None
    user.ban_reason = None
    user.token = jwt.encode(user_asdict(user),
                            user.token_secret,
                            algorithm="HS256")

    for app_user in AppUser.query.filter_by(id=user.id).all():
        app_user.token = jwt.encode(user_asdict(user),
                                    app_user.app.secret,
                                    algorithm="HS256")

    db.session.commit()

    subject = "Ban Notice"
    body = (f"Hello {escape(account.name)}!\n\n"
            "A moderator has unbanned your account.\n\n"
            "Please read our Terms of Service and "
            "refer to your ban reason to avoid future bans"
            "We hope you understand. Thanks for using Connext!")

    email_send(user.email, subject, body)

    return {"text": f"Unbanned '{user.name}'.",
            "user": user_asdict(user)}, 200


# OAuth


@flask.route("/oauth/authorize")
@auth(True, "/login")
@args_key("response_type")
@args_key("app_id", 12, 12, int)
def oauth_authorize(account, response_type, app_id):
    if response_type == "token":
        app = App.query.filter_by(id=app_id).first()
        if not app:
            return render_template("not_found.html",
                                   error="App does not exist!"), 404

        elif not app.approved:
            return render_template("forbidden.html",
                                   error="App isn't approved!"), 403

        app_user = AppUser.query.filter_by(app_id=app.id,
                                           id=account.id).first()

        if app_user:
            return redirect(app.callback + f"#token={app_user.token}")

        return render_template("oauth_authorize.html",
                               app=app_asdict(app),
                               owner=user_asdict(app.owner),
                               account=user_asdict(account))

    else:
        return {"text": "Response type not supported!",
                "error": "invalid_response_type"}, 400


@flask.route("/oauth/deauthorize", methods=["POST"])
@auth(True)
@json_key("app_id", 12, 12, int)
def oauth_deauthorize(account, app_id):
    app = App.query.filter_by(id=app_id).first()
    if not app:
        return {"text": "App does not exist!",
                "error": "invalid_app_id"}, 404

    app_user = AppUser.query.filter_by(app_id=app.id,
                                       id=account.id).first()

    if not app_user:
        return {"You are not logged into this app!", "invalid_app_id"}

    app_user.delete()

    db.session.commit()

    return {"text": f"Deauthorized app '{app.name}'.",
            "app": app_asdict(app)}, 200


@flask.route("/oauth/register", methods=["POST"])
@ratelimit
@auth(True)
@captcha3
@json_key("response_type")
@json_key("app_id", 12, 12, int)
def oauth_register(account, response_type, app_id):
    if response_type == "token":
        app = App.query.filter_by(id=app_id).first()
        if not app:
            return {"text": "App does not exist!",
                    "error": "invalid_app_id"}, 404

        elif not app.approved:
            return {"text": "App isn't approved!",
                    "error": "app_unapproved"}, 403

        app_user = AppUser.query.filter_by(app_id=app.id,
                                           id=account.id).first()

        if app_user:
            return {"text": "Token granted.", "token": app_user.token}

        token = jwt.encode(user_asdict(account),
                           app.secret,
                           algorithm="HS256")

        db.session.add(AppUser(app_id=app.id,
                               id=account.id,
                               token=token))

        db.session.commit()

        subject = "App Added"
        ip = IP(request.headers.get('CF-Connecting-IP'))
        body = (f"Hello {escape(account.name)}!\n\n"
                f"The app {escape(app.name)} was added to your account!\n\n"
                "If this was not you, reset your password immediately and "
                "enable 2FA if possible, then remove the app.\n\n"
                f"Logged in at {ip.location} by {ip.address}")

        email_send(account.email, subject, body)

        return {"text": f"Token created for '{account.name}'.",
                "token": token, "account": user_asdict(account)}, 200
    else:
        return {"text": "Response type not supported!",
                "error": "invalid_response_type"}, 400


@flask.route("/oauth/user")
@args_key("token", 1, 256)
def oauth_user(token):
    app_user = AppUser.query.filter_by(token=token).first()
    if not app_user:
        return {"text": "Invalid token!", "error": "invalid_token"}, 401

    user = app_user.user
    if not user:
        return {"text": "User does not exist!",
                "error": "invalid_user"}, 404

    if user.banned:
        return {"text": "User is banned!", "error": "user_banned"}, 403
    elif not user.verified:
        return {"text": "User is not verified!",
                "error": "user_unverified"}, 403

    app = app_user.app
    if not app:
        return {"text": "App does not exist!",
                "error": "invalid_app"}, 404

    elif not app.approved:
        return {"text": "App isn't approved!",
                "error": "app_unapproved"}, 403

    return user_asdict(user), 200


# Developer


@flask.route("/api/apps/<int:id>")
@auth(False)
def api_apps_id(account, id):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    app = App.query.filter_by(id=id).first()
    if not app:
        return {"text": "App does not exist!",
                "error": "invalid_app_id"}, 404

    app_dict = app_asdict(app)

    if account:
        if account.id == app.owner.id:
            app_dict["secret"] = app.secret

    return app_dict, 200


@flask.route("/api/apps/create", methods=["POST"])
@ratelimit
@auth(True)
# @captcha3
@json_key("callback", 8, 128)
@json_key("name", 1, 32)
@json_key("website", 8, 32)
def api_apps_create(account, callback, name, website):
    if "#" in callback:
        return {"text": "Callback must not contain #!",
                "error": "invalid_callback"}

    id = gen_id(2, App, "id")

    secret = gen_token(App, "secret")

    if callback[:7] != "http://" and callback[:8] != "https://":
        callback = "https://" + callback

    website.replace("http://", "").replace("https://", "")

    db.session.add(App(id=id,
                       owner_id=account.id,
                       secret=secret,
                       callback=callback,
                       name=name,
                       website=website,
                       approved=False,
                       verified=False))

    db.session.commit()

    return {"text": f"App '{name}' created.",
            "app": app_asdict(App.query.filter_by(id=id).first())}, 200


@flask.route("/api/apps/<int:id>/update", methods=["POST"])
@ratelimit
@auth(True)
# @captcha3
@json_key("callback", 8, 128, required=False)
@json_key("name", 1, 32, required=False)
@json_key("website", 8, 32, required=False)
def api_apps_update(account, id, callback, name, website):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if callback:
        if "#" in callback:
            return {"text": "Callback must not contain #!",
                    "error": "invalid_callback"}

    app = App.query.filter_by(id=id).first()
    if not app:
        return {"text": "App does not exist!",
                "error": "invalid_app_id"}, 404

    elif account.id != app.owner.id:
        return {"text": "You do not own this app!",
                "error": "no_app_access"}, 403

    if callback[:7] != "http://" and callback[:8] != "https://":
        callback = "https://" + callback

    callback.replace("http://", "").replace("https://", "")

    if callback:
        app.callback = callback

    if name:
        app.name = name

    if website:
        app.website = website

    for app_user in AppUser.query.filter_by(app_id=app.id).all():
        app_user.delete()

    db.session.commit()

    return {"text": f"App '{app.name}' updated.",
            "app": app_asdict(app)}, 200


@flask.route("/api/apps/<int:id>/reset", methods=["POST"])
@ratelimit
@auth(True)
# @captcha3
def api_apps_reset(account, id):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    app = App.query.filter_by(id=id).first()
    if not app:
        return {"text": "App does not exist!",
                "error": "invalid_app_id"}, 404

    elif account.id != app.owner.id:
        return {"text": "You do not own this app!",
                "error": "no_app_access"}, 403

    for app_user in AppUser.query.filter_by(app_id=app.id).all():
        app_user.delete()

    app.secret = gen_token(App, "secret")

    db.session.commit()

    return {"text": f"App '{app.name}' reset.", "app": app_asdict(app)}, 200


@flask.route("/api/apps/<int:id>/delete", methods=["POST"])
@ratelimit
@auth(True)
# @captcha3
def api_apps_delete(account, id):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    app = App.query.filter_by(id=id).first()
    if not app:
        return {"text": "App does not exist!",
                "error": "invalid_app_id"}, 404

    elif account.id != app.owner.id:
        return {"text": "You do not own this app!",
                "error": "no_app_access"}, 403

    app.delete()

    db.session.commit()

    return {"text": f"App '{app.name}' deleted.", "app": app_asdict(app)}, 200


# App Tools


@flask.route("/api/apps/<int:id>/refresh", methods=["POST"])
@ratelimit
@json_key("secret", 256, 256)
def api_apps_refresh(id, secret):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    app = App.query.filter_by(id=id).first()
    if not app:
        return {"text": "App does not exist!",
                "error": "invalid_app_id"}, 404

    elif secret != app.secret:
        return {"text": "You do not have access to this app!",
                "error": "invalid_secret"}, 403

    users = []
    for app_user in AppUser.query.filter_by(app_id=app.id).all():
        token = jwt.encode(user_asdict(app_user.user),
                           app.secret,
                           algorithm="HS256")

        users.append({"id": app_user.id, "token": token})

    return {"users": users}, 200


@flask.route("/api/apps/<int:id>/users/<int:user_id>/refresh",
             methods=["POST"])

@ratelimit
@json_key("secret", 256, 256)
def api_apps_user_refresh(id, user_id, secret):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    app = App.query.filter_by(id=id).first()
    if not app:
        return {"text": "App does not exist!",
                "error": "invalid_app_id"}, 404

    elif secret != app.secret:
        return {"text": "You do not have access to this app!",
                "error": "invalid_secret"}, 403

    app_user = AppUser.query.filter_by(app_id=app.id).all()

    token = jwt.encode(user_asdict(app_user.user),
                       app.secret,
                       algorithm="HS256")

    return {"id": app_user.id, "token": token}, 200


# Admin


@flask.route("/api/apps")
@auth(True)
def api_apps(account):
    if not account.permission >= 2:
        return {"text": "Insufficient permissions!"}, 403

    apps = []
    for app in App.query.all():
        apps.append(app_asdict(app))

    return {"apps": apps}, 200


@flask.route("/api/apps/<int:id>/approve", methods=["POST"])
@ratelimit
@auth(True)
def api_apps_approve(account, id):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if not account.permission >= 2:
        return {"text": "Insufficient permissions!"}, 403

    app = App.query.filter_by(id=id).first()
    if not app:
        return {"text": "App does not exist!", "error": "invalid_app_id"}, 404

    app.approved = True

    db.session.commit()

    return {"text": f"App '{app.name}' approved.",
            "app": app_asdict(app)}, 200


@flask.route("/api/apps/<int:id>/verify", methods=["POST"])
@ratelimit
@auth(True)
def api_apps_verify(account, id):
    if not id:
        return {"text": "Please specify a value for 'id'!",
                "error": "invalid_id"}, 400

    if not isinstance(id, int):
        return {"text": ("Value for 'id' must be type "
                         "int!"),
                "error": "invalid_id"}, 400

    if len(str(id)) < 12:
        return {"text": ("Value for 'id' must be at least "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if len(str(id)) > 12:
        return {"text": ("Value for 'id' must be at most "
                         "12 characters!"),
                "error": "invalid_id"}, 400

    if not account.permission >= 2:
        return {"text": "Insufficient permissions!"}, 403

    app = App.query.filter_by(id=id).first()
    if not app:
        return {"text": "App does not exist!", "error": "invalid_app_id"}, 404

    app.approved = True
    app.verified = True

    db.session.commit()

    return {"text": f"App '{app.name}' verified.",
            "app": app_asdict(app)}, 200


"""
# Relationships


@flask.route("/api/relationships/<int:name>/create", methods=["POST"])
@ratelimit
@auth(True)
def api_relationships_create(account, name):
    if not name:
        return {"text": "Please specify a value for 'name'!",
                "error": "invalid_name"}, 400

    if not isinstance(name, str):
        return {"text": ("Value for 'name' must be type "
                         "str!"),
                "error": "invalid_name"}, 400

    if len(name) < 1:
        return {"text": ("Value for 'name' must be at least "
                         "1 character!"),
                "error": "invalid_name"}, 400

    if len(name) > 32:
        return {"text": ("Value for 'name' must be at most "
                         "32 characters!"),
                "error": "invalid_name"}, 400

    user = User.query.filter_by(name=name).first()
    if not user:
        return {"text": "User does not exist!",
                "error": "invalid_user_id"}, 404

    elif user.banned:
        return {"text": "User is banned!", "error": "user_banned"}, 403
    elif not user.verified:
        return {"text": "User is not verified!",
                "error": "user_unverified"}, 403

    relationship = UserRelationship.query.filter_by(user_id=account.id,
                                                    id=user.id).first()

    recipient_relationship = (UserRelationship
                              .query.filter_by(user_id=user.id,
                                               id=account.id).first())

    if relationship:
        if relationship.status == 2 and not recipient_relationship:
            relationship.status = 0
            return {"text": f"Relationship with '{user.name}' requested.",
                    "user": user_asdict(user)}, 200

        return {"text": "Relationship already exists!",
                "error": "relationship_exists"}, 403

    if recipient_relationship:
        if recipient_relationship.status == 2:
            return {"text": "You are blocked by this user!",
                    "error": "account_blocked"}, 403

        elif recipient_relationship.status == 0:
            recipient_relationship.status = 1

            db.session.add(UserRelationship(user_id=account.id,
                                            id=user.id,
                                            status=1))

            db.session.commit()

            return {"text": f"Relationship with '{user.name}' created.",
                    "user": user_asdict(user)}, 200

    db.session.add(UserRelationship(user_id=account.id, id=user.id, status=0))

    db.session.commit()

    return {"text": f"Relationship with '{user.name}' requested.",
            "user": user_asdict(user)}, 200
"""


# Thanks for using Connext Accounts!
# Look forward to more updates, this version contains very baseline features
# 2FA will also be available in the future, hooray!
# -Isaac/Aizakku


if __name__ == "__main__":
    flask.run()
