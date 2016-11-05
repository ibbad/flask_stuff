from flask import Flask, request, make_response, redirect, abort, session
from flask import url_for, flash
from flask import render_template
from flask.ext.bootstrap import Bootstrap
from flask.ext.script import Manager, Server, Shell
from flask.ext.moment import Moment
from flask.ext.migrate import Migrate, MigrateCommand
from flask.ext.mail import Mail
from flask.ext.mail import Message
from flask.ext.wtf import Form
from flask.ext.sqlalchemy import SQLAlchemy
from wtforms import StringField, SubmitField
from wtforms.validators import Required
from datetime import datetime
import os
from threading import Thread

app = Flask(__name__)
bootstrap = Bootstrap(app)
moment = Moment(app)



basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SQLALCHEMY_DATABASE_URI'] = \
                        'sqlite:///' +os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SECRET_KEY'] = 'a very hard to find key potato'

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'emailusername'
app.config['MAIL_PASSWORD'] = '*************'
app.config['FLASKY_MAIL_SUBJECT_PREFIX'] = '[FLASKY]'
app.config['FLASKY_MAIL_SENDER'] = os.environ.get('FLASKY_ADMIN') or \
                                   'Flasky Admin <flasky@example.com>'
app.config['FLASKY_ADMIN'] = os.environ.get('FLASKY_ADMIN')

mail = Mail(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

manager = Manager(app)

# Models
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column (db.String(64), unique=True)
    users = db.relationship('User', backref = 'role')   # one to many relationship

    def __repr__(self):
        return '<Role %r>' % self.name

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def __repr__ (self):
        return '<User %r>' % self.username

class NameForm(Form):
    name = StringField('What is your name?', validators=[Required()])
    submit = SubmitField('Submit')

def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role)

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_mail(to, subject, template, **kwargs):
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX']+ subject,
                  sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])

    msg.body = render_template(template+'.txt', **kwargs)
    msg.html = render_template(template+'.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('404.html'), 4500

@app.route('/')
def index():
    user_agent = request.headers.get('User-Agent')
    return '<h1> Hello World </h1></br><p> Your browser is %s</p>' % user_agent

@app.route('/index_template', methods=['GET', 'POST'])
def index1():
    name = None
    form = NameForm()
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
    return render_template('index.html', form=form, name=name,
                           current_time=datetime.utcnow())

@app.route('/index_session', methods=['GET', 'POST'])
def index2():
    form = NameForm()
    if form.validate_on_submit():
        session['name'] = form.name.data
        return redirect(url_for('index2'))
    return render_template('index.html',
                           form=form,
                           name=session.get('name'),
                           current_time=datetime.utcnow())

@app.route('/index_flash', methods=['GET', 'POST'])
def index3():
    form = NameForm()
    if form.validate_on_submit():
        old_name = session.get('name')
        if old_name is not None and old_name != form.name.data:
            flash('You changed your name???')
        session['name'] = form.name.data
        form.name.data = ''
        return redirect(url_for('index3'))
    return render_template('index.html',
                           form = form,
                           name = session.get('name'),
                           current_time = datetime.utcnow())

@app.route("/index_database", methods=['GET', 'POST'])
def index4():
    form = NameForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.name.data).first()
        if user is None:
            user = User(username=form.name.data)
            db.session.add(user)
            session['known'] = False
        else:
            session['known'] = True
        session['name'] = form.name.data
        form.name.data = ''
        return redirect(url_for('index4'))
    return render_template('index.html', form=form, name=session.get('name'),
                           known = session.get('known', False),
                           current_time=datetime.utcnow())

@app.route("/index_mail", methods=['GET', 'POST'])
def index5():
    form = NameForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.name.data).first()
        if user is None:
            user = User(username=form.name.data)
            db.session.add(user)
            session['known'] = False
            if app.config['FLASKY_ADMIN']:
                send_email(app.config['FLASKY_ADMIN'], 'New User',
                           'mail/new_user', user=user)
        else:
            session['known'] = True
        session['name'] = form.name.data
        form.name.data = ''
        return redirect(url_for('index5'))
    return render_template('index.html', form=form, name=session.get('name'),
                           known = session.get('known', False),
                           current_time=datetime.utcnow())

@app.route('/user/<name>')
def user(name):
    # return '<h1> Hello, %s</h1>' %name
    return render_template('user.html', name=name)

@app.route('/bad_request')
def bad_request():
    return '<h1>Bad Request</h1>', 400

@app.route('/get_cookie')
def get_cookie():
    response = make_response('<h1>This document carries a cookie!</h1>')
    response.set_cookie('answer', '42')
    return response

@app.route('/redirect_me')
def redirection():
    return redirect('http://www.google.com')

@app.route('/abort_me')
def abortion():
    abort(404)

if __name__ == "__main__":
    manager.add_command('db', MigrateCommand)
    manager.add_command("shell", Shell(make_context=make_shell_context))
    manager.run()
    # app.run(debug=True)
