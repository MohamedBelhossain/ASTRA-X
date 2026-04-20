from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from .models import User, ResetToken
import random
import string

bcrypt = Bcrypt()
mail   = Mail()
auth   = Blueprint("auth", __name__)


def generate_code():
    return ''.join(random.choices(string.digits, k=6))


# ─────────────────────────────────────────
#  REGISTER
# ─────────────────────────────────────────
@auth.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("auth.register"))

        if User.find_by_email(email):
            flash("Email already registered.", "danger")
            return redirect(url_for("auth.register"))

        if User.find_by_username(username):
            flash("Username already taken.", "danger")
            return redirect(url_for("auth.register"))

        code = generate_code()
        session["pending_user"] = {
            "username": username,
            "email":    email,
            "password": bcrypt.generate_password_hash(password).decode("utf-8"),
            "code":     code
        }

        _send_mail(
            to=email,
            subject="WebVulnScan — Verify your email",
            body=f"Your verification code is: {code}\n\nExpires in 10 minutes."
        )

        flash("A 6-digit code has been sent to your email.", "success")
        return redirect(url_for("auth.verify_email"))

    return render_template("register.html")


# ─────────────────────────────────────────
#  VERIFY EMAIL
# ─────────────────────────────────────────
@auth.route("/verify", methods=["GET", "POST"])
def verify_email():
    if "pending_user" not in session:
        return redirect(url_for("auth.register"))

    if request.method == "POST":
        entered = request.form.get("code", "").strip()
        pending = session["pending_user"]

        if entered == pending["code"]:
            User.create(
                username        = pending["username"],
                email           = pending["email"],
                hashed_password = pending["password"]
            )
            User.set_verified(pending["email"])
            session.pop("pending_user", None)
            flash("Email verified! Please log in.", "success")
            return redirect(url_for("auth.login"))
        else:
            flash("Invalid code. Try again.", "danger")

    return render_template("verify.html")


# ─────────────────────────────────────────
#  LOGIN
# ─────────────────────────────────────────
@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email    = request.form.get("email", "").strip()
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
        email = request.form.get("email", "").strip()
        user  = User.find_by_email(email)

        if user:
            code = generate_code()
            ResetToken.create(email=email, code=code)
            _send_mail(
                to=email,
                subject="WebVulnScan — Reset your password",
                body=f"Your password reset code is: {code}\n\nExpires in 10 minutes.\nIf you did not request this, ignore this email."
            )

        flash("If this email exists, a reset code has been sent.", "success")
        return redirect(url_for("auth.reset_password"))

    return render_template("forgot_password.html")


# ─────────────────────────────────────────
#  RESET PASSWORD
# ─────────────────────────────────────────
@auth.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        code     = request.form.get("code", "").strip()
        password = request.form.get("password", "").strip()
        confirm  = request.form.get("confirm_password", "").strip()

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("auth.reset_password"))

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for("auth.reset_password"))

        token = ResetToken.find_valid(email=email, code=code)
        if not token:
            flash("Invalid or expired code.", "danger")
            return redirect(url_for("auth.reset_password"))

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        User.update_password(email=email, hashed_password=hashed)
        ResetToken.mark_used(email=email, code=code)

        flash("Password updated! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html")


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
    msg = Message(subject=subject, recipients=[to], body=body)
    mail.send(msg)