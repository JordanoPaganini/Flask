from flask import Flask, render_template, redirect, Blueprint, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user
from flask_migrate import Migrate

# Settings
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://eventos_admin:eventos_admin15*@db4free.net/eventos_mpa'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

auth = Blueprint('auth', __name__)

app.register_blueprint(auth, url_prefix='/auth')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

migrate = Migrate(app, db)

# Routes

@app.route('/')
def index():
    return redirect('/index.html')

@app.route('/index.html')
def main():
    return render_template('index.html')

@login_manager.user_loader
def load_user(user_id):
 return User.query.get(int(user_id))


@app.route('/login', methods= ['POST'])
def login():
    print('OI' * 50)
    user = User.query.filter_by(email=request.form['username']).first()
    if user is not None and user.verify_password(request.form['password']):
        login_user(user.id)
        if next is None or not next.startswith('/'):
            next = url_for('main.index')
        return redirect('/index.html')
    flash('Invalid username or password.')
    return render_template('index.html')

# Models

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return '<User %r>' % self.username
    
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')
    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0