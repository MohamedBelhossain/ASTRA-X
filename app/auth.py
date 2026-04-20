import random
import string
import time

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_bcrypt import Bcrypt
from flask_login import current_user, login_required, login_user, logout_user
from flask_mail import Mail, Message

from .models import ResetToken, User

bcrypt = Bcrypt()
mail   = Mail()
auth   = Blueprint("auth", __name__)
CODE_TTL_SECONDS = 600
MIN_PASSWORD_LENGTH = 6


def generate_code():
    return "".join(random.choices(string.digits, k=6))


def normalize_email(email):
    return email.strip().lower()


def sanitize_code(code):
    return "".join(ch for ch in code if ch.isdigit())


def _new_expiry_timestamp():
    return int(time.time()) + CODE_TTL_SECONDS


def _is_pending_code_expired(pending):
    return int(time.time()) > int(pending.get("code_expires_at", 0))


def _issue_pending_code(pending):
    pending["code"] = generate_code()
    pending["code_expires_at"] = _new_expiry_timestamp()
    session["pending_user"] = pending
    session.modified = True
    return pending["code"]


def _send_verification_code(pending):
    code = pending.get("code") or _issue_pending_code(pending)
    return _send_mail(
        to=pending["email"],
        subject="WebVulnScan — Verify your email",
        body=(
            f"Your verification code is: {code}\n\n"
            "Expires in 10 minutes."
        ),
    )


# ─────────────────────────────────────────
#  REGISTER
# ─────────────────────────────────────────
@auth.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "").strip()
        confirm  = request.form.get("confirm_password", "").strip()
        form_data = {"username": username, "email": email}

        if not username or not email or not password or not confirm:
            flash("All fields are required.", "danger")
            return render_template("register.html", form_data=form_data)

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", form_data=form_data)

        if len(password) < MIN_PASSWORD_LENGTH:
            flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", "danger")
            return render_template("register.html", form_data=form_data)

        if User.find_by_email(email):
            flash("Email already registered.", "danger")
            return render_template("register.html", form_data=form_data)

        if User.find_by_username(username):
            flash("Username already taken.", "danger")
            return render_template("register.html", form_data=form_data)

        pending_user = {
            "username": username,
            "email":    email,
            "password": bcrypt.generate_password_hash(password).decode("utf-8"),
            "code":     "",
            "code_expires_at": 0,
        }
        _issue_pending_code(pending_user)

        if not _send_verification_code(session["pending_user"]):
            flash("Verification email could not be sent. Configure MAIL_USERNAME, MAIL_PASSWORD, and MAIL_DEFAULT_SENDER in .env.", "danger")
            return render_template("register.html", form_data=form_data)

        flash("A 6-digit code has been sent to your email.", "success")
        return redirect(url_for("auth.verify_email"))

    return render_template("register.html", form_data={})


# ─────────────────────────────────────────
#  VERIFY EMAIL
# ─────────────────────────────────────────
@auth.route("/verify", methods=["GET", "POST"])
def verify_email():
    if "pending_user" not in session:
        flash("Start by creating your account first.", "warning")
        return redirect(url_for("auth.register"))

    pending = session["pending_user"]

    if request.method == "POST":
        entered = sanitize_code(request.form.get("code", ""))

        if len(entered) != 6:
            flash("Enter the 6-digit verification code.", "danger")
            return render_template(
                "verify.html",
                pending_email=pending["email"],
                code_value=entered,
                code_expired=_is_pending_code_expired(pending),
            )

        if _is_pending_code_expired(pending):
            flash("Your verification code expired. Request a new one below.", "danger")
            return render_template(
                "verify.html",
                pending_email=pending["email"],
                code_value=entered,
                code_expired=True,
            )

        if entered == pending["code"]:
            if User.find_by_email(pending["email"]):
                session.pop("pending_user", None)
                flash("That email is already registered. Please sign in instead.", "warning")
                return redirect(url_for("auth.login"))

            if User.find_by_username(pending["username"]):
                session.pop("pending_user", None)
                flash("That username is no longer available. Please register again.", "warning")
                return redirect(url_for("auth.register"))

            User.create(
                username        = pending["username"],
                email           = pending["email"],
                hashed_password = pending["password"]
            )
            User.set_verified(pending["email"])
            session.pop("pending_user", None)
            flash("Email verified! Please log in.", "success")
            return redirect(url_for("auth.login"))

        flash("Invalid code. Try again.", "danger")
        return render_template(
            "verify.html",
            pending_email=pending["email"],
            code_value=entered,
            code_expired=False,
        )

    return render_template(
        "verify.html",
        pending_email=pending["email"],
        code_value="",
        code_expired=_is_pending_code_expired(pending),
    )


@auth.route("/verify/resend", methods=["POST"])
def resend_verification_code():
    pending = session.get("pending_user")
    if not pending:
        flash("Start by creating your account first.", "warning")
        return redirect(url_for("auth.register"))

    _issue_pending_code(pending)
    if not _send_verification_code(session["pending_user"]):
        flash("Verification email could not be resent. Check MAIL_USERNAME, MAIL_PASSWORD, and MAIL_DEFAULT_SENDER in .env.", "danger")
        return redirect(url_for("auth.verify_email"))

    flash("A new verification code has been sent.", "success")
    return redirect(url_for("auth.verify_email"))


# ─────────────────────────────────────────
#  LOGIN
# ─────────────────────────────────────────
@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email    = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "").strip()
        user     = User.find_by_email(email)

        if not user or not bcrypt.check_password_hash(user.password, password):
            flash("Invalid email or password.", "danger")
            return redirect(url_for("auth.login"))

        if not user.is_verified:
            flash("Please verify your email before logging in.", "warning")
            return redirect(url_for("auth.login"))

        login_user(user)
        return redirect(url_for("index"))

    return render_template("login.html")


# ─────────────────────────────────────────
#  FORGOT PASSWORD
# ─────────────────────────────────────────
@auth.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = normalize_email(request.form.get("email", ""))
        user  = User.find_by_email(email)

        if not email:
            flash("Email is required.", "danger")
            return render_template("forgot_password.html", email_value=email)

        if user:
            code = generate_code()
            ResetToken.create(email=email, code=code)
            if not _send_mail(
                to=email,
                subject="WebVulnScan — Reset your password",
                body=(
                    f"Your password reset code is: {code}\n\n"
                    "Expires in 10 minutes.\n"
                    "If you did not request this, ignore this email."
                ),
            ):
                flash("Reset email could not be sent. Configure MAIL_USERNAME, MAIL_PASSWORD, and MAIL_DEFAULT_SENDER in .env.", "danger")
                return render_template("forgot_password.html", email_value=email)

        session["pending_reset_email"] = email

        flash("If this email exists, a reset code has been sent.", "success")
        return redirect(url_for("auth.reset_password"))

    return render_template("forgot_password.html", email_value=session.get("pending_reset_email", ""))


# ─────────────────────────────────────────
#  RESET PASSWORD
# ─────────────────────────────────────────
@auth.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email    = normalize_email(request.form.get("email", ""))
        code     = sanitize_code(request.form.get("code", ""))
        password = request.form.get("password", "").strip()
        confirm  = request.form.get("confirm_password", "").strip()
        form_data = {"email": email, "code": code}

        if not email or not code or not password or not confirm:
            flash("All fields are required.", "danger")
            return render_template("reset_password.html", form_data=form_data)

        user = User.find_by_email(email)
        if not user:
            flash("No account was found for that email.", "danger")
            return render_template("reset_password.html", form_data=form_data)

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", form_data=form_data)

        if len(password) < MIN_PASSWORD_LENGTH:
            flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", "danger")
            return render_template("reset_password.html", form_data=form_data)

        if len(code) != 6:
            flash("Enter the 6-digit reset code.", "danger")
            return render_template("reset_password.html", form_data=form_data)

        token = ResetToken.find_valid(email=email, code=code)
        if not token:
            flash("Invalid or expired code.", "danger")
            return render_template("reset_password.html", form_data=form_data)

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        User.update_password(email=email, hashed_password=hashed)
        ResetToken.mark_used(email=email, code=code)
        session.pop("pending_reset_email", None)

        flash("Password updated! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template(
        "reset_password.html",
        form_data={"email": session.get("pending_reset_email", ""), "code": ""},
    )


@auth.route("/reset-password/resend", methods=["POST"])
def resend_reset_code():
    email = normalize_email(request.form.get("email", ""))
    session["pending_reset_email"] = email

    if not email:
        flash("Enter your email before requesting a new reset code.", "danger")
        return redirect(url_for("auth.reset_password"))

    user = User.find_by_email(email)
    if user:
        code = generate_code()
        ResetToken.create(email=email, code=code)
        if not _send_mail(
            to=email,
            subject="WebVulnScan — Reset your password",
            body=(
                f"Your password reset code is: {code}\n\n"
                "Expires in 10 minutes.\n"
                "If you did not request this, ignore this email."
            ),
        ):
            flash("Reset email could not be resent. Check MAIL_USERNAME, MAIL_PASSWORD, and MAIL_DEFAULT_SENDER in .env.", "danger")
            return redirect(url_for("auth.reset_password"))

    flash("If this email exists, a new reset code has been sent.", "success")
    return redirect(url_for("auth.reset_password"))


# ─────────────────────────────────────────
#  LOGOUT
# ─────────────────────────────────────────
@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


# ─────────────────────────────────────────
#  HELPER
# ─────────────────────────────────────────
def _send_mail(to, subject, body):
    username = (current_app.config.get("MAIL_USERNAME") or "").strip()
    password = (current_app.config.get("MAIL_PASSWORD") or "").strip()
    default_sender = (current_app.config.get("MAIL_DEFAULT_SENDER") or "").strip()

    placeholders = {
        "",
        "your_email@gmail.com",
        "your_16char_app_password",
    }
    if (
        username in placeholders
        or password in placeholders
        or default_sender in {"", "your_email@gmail.com"}
    ):
        current_app.logger.warning("Mail sending skipped because SMTP settings are not configured.")
        return False

    try:
        msg = Message(subject=subject, recipients=[to], body=body)
        mail.send(msg)
        return True
    except Exception as exc:
        current_app.logger.exception("Mail sending failed: %s", exc)
        return False
