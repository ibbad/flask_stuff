from flask import Flask, request, make_response, redirect, abort
from flask import render_template
from flask.ext.bootstrap import Bootstrap
from flask.ext.script import Manager
from flask.ext.moment import Moment
from flask.ext.wtf import Form
from wtforms import StringField, SubmitField
from wtforms.validators import Required
from datetime import datetime

app = Flask(__name__)
manager = Manager(app)
bootstrap = Bootstrap(app)
moment = Moment(app)

app.config['SECRET_KEY'] = 'a very hard to find key potato'

class NameForm(Form):
    name = StringField('What is your name?', validators=[Required()])
    submit = SubmitField('Submit')

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
    # manager.run()
    app.run(debug=True)
