from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            print(password)
            if check_password_hash(user.password, password):
                flash("Logged in Successfully !", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash("Invalid Credentials !", category='error')
        else:
            flash("User does not exist !", category='error')

    return render_template("login.html", user = current_user)

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        firstname = request.form.get('firstname')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email already in use !", category='error')
        elif len(email) < 4:
            flash("Email invalid", category='error')
        elif len(firstname) < 2:
            flash("Firstname Error", category='error')
        elif password1 != password2:
            flash("Passwords don\'t match !", category='error')
        elif len(password1) < 7:
            flash("Password length Error", category='error')
        else:
            new_user = User(email = email, firstname = firstname, password = generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user)
            flash("Account Created !", category='success')
            return redirect(url_for('views.home'))

    return render_template("signup.html", user = current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template("login.html", user = current_user)
