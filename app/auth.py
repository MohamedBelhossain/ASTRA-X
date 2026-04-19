
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from .models import User

bcrypt = Bcrypt()
auth = Blueprint("auth", __name__)


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

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        User.create(username=username, email=email, hashed_password=hashed_pw)

        flash("Account created! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


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

        login_user(user)
        return redirect(url_for("index"))

    return render_template("login.html")


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))
