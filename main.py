from flask import Flask, redirect, url_for, render_template, request, session, flash
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt

app = Flask(__name__)
# one time secret key for sessions
app.secret_key = 'cnG*DS8@wFZNly95F5d#'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Set the default life of a session
# once ready set the following to 15 minutes
app.permanent_session_lifetime = timedelta(minutes=5)

db = SQLAlchemy(app)

# User object which is used to store username,password and email to db.
class user_list(db.Model):
    _id = db.Column('id', db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    password = db.Column(db.String(256))

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/features')
def features():
    return render_template('features.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user' in session:
        return redirect(url_for('user'))
    if request.method == 'POST':
        # saving form data to following three variables
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        # hashing the password
        secure_password = sha256_crypt.hash(str(password))
        # checking if the user is already registered
        found_user = user_list.query.filter_by(name=username).first()
        if found_user:
            # if the user is already registered, letting the user know that he/she is already registered
            flash(f'{username} is already registered', 'info')
        else:
            # Create new user object
            new_user = user_list(username, email, secure_password)
            # adding new user to the the db
            db.session.add(new_user)
            # committing the changes to the db.
            db.session.commit()
            # flashing the successful message to the user
            flash(f'Successfully registered, {username}', 'info')
        # redirecting user to the login page
        return redirect(url_for('login'))
    # default redirecting user to register page
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # following statement will make sessions alive on for above declared time
        session.permanent = True
        # receiving inputs from the form and saving them in local variables
        username = request.form['user']
        password = request.form['password']
        # Need to authenticate information
        # checking if user exists in the db
        found_user = user_list.query.filter_by(name=username).first()
        # checking if the user's password matches with what is saved in the db
        if found_user and sha256_crypt.verify(password, found_user.password):
            # saving following variables to the session
            session['user'] = username
            session['email'] = found_user.email
            # redirecting user to his/her profile page
            return redirect(url_for('user'))
        else:
            # flashing the message that the credentials were incorrect
            flash(f'Incorrect credentials , {username}', 'info')
            # redirecting the user back to login prompt page
            return redirect(url_for('login'))
    # if the user in session and user browses to /login page he will be redirected to the user profile page
    else:
        if 'user' in session:
            return redirect(url_for('user'))
        # by default Login page will be rendered
        return render_template('login.html')


@app.route('/simsim', methods=['POST', 'GET'])
def user():
    email = None
    if 'user' in session:
        user = session['user']
        if request.method == 'POST':
            email = request.form['email']
            session['email'] = email
            found_user = user_list.query.filter_by(name=user).first()
            found_user.email = email
            db.session.commit()
            flash(f'New Email saved', 'info')
        else:
            if 'email' in session:
                email = session['email']
        return render_template('user.html', user=user, email=email)
    else:
        return redirect(url_for('login'))


@app.route('/view')
def view():
    # only for diagnostics purposes. This page will show the entire user_list db.
    return render_template('view.html', values=user_list.query.all())


@app.route('/logout')
def logout():
    # if session.pop checks if the user in session
    # following will also remove the user from the session
    if 'user' in session:
        username = session.pop('user', None)  # removes and returns the user from the session
        session.pop('email', None)  # removes and returns the user's email from the session
        flash(f'Logged out successfully, {username}', 'info')
    return redirect(url_for('login'))


db.create_all()
app.run(host='127.0.0.1', port=8080)
