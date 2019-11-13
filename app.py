
from flask import Flask, url_for, render_template, request, redirect, make_response
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from wtforms.ext.sqlalchemy.fields import QuerySelectField
from wtforms.widgets import TextArea
from hashlib import sha256 as SHA256
import flask_login
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
import subprocess
from subprocess import check_output
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from sqlalchemy import create_engine, Column, Integer, ForeignKey, String, DateTime 
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from secrets import token_hex
from datetime import datetime
import os.path

BASE = declarative_base()
DBFILE = "users.db"

def setup_db():
    global BASE
    engine = create_engine(f'sqlite:///{DBFILE}')
    BASE.metadata.bind = engine
    if not(os.path.isfile(DBFILE)):
        BASE.metadata.create_all(engine)
        DBSessionMaker = sessionmaker(bind=engine)
        session = DBSessionMaker()
        #ADD ADMINISTRATOR
        hasher = SHA256()
        pword = "Administrator@1" 
        hasher.update(pword.encode('utf-8'))
        uname = "admin"
        salt = token_hex(nbytes=16)
        hasher.update(salt.encode('utf-8'))
        passwordhash = hasher.hexdigest()
        mfa = "12345678901"
        new_user = Users(uname=uname, pword=passwordhash, mfa=mfa, salt=salt)
        session.add(new_user)
        session.commit()
        session.close()
    else:
        DBSessionMaker = sessionmaker(bind=engine)
    return DBSessionMaker

class Users(BASE):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    uname = Column(String(25), nullable=False, unique=True)
    pword = Column(String(64), nullable=False)
    mfa = Column(String(25), nullable=False)
    salt = Column(String(16), nullable=False)


class LoginRecord(BASE):
    __tablename__ = 'login_records'
    record_number = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.uname'), nullable=False)
    time_on = Column(DateTime, nullable=False)
    time_off = Column(DateTime)
    users = relationship(Users)


class RecordHistory(BASE):
    __tablename__ = 'record_history'
    record_number = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.uname'), nullable=False)
    query_text = Column(String(256), nullable=False)
    query_result = Column(String(256))
    users = relationship(Users)

login_manager = flask_login.LoginManager()


# Flask Forms user for page rendering
class RegistrationForm(FlaskForm):
    uname = StringField('Username', [validators.Length(min=4, max=25)])
    pword = PasswordField('New Password', [
            validators.DataRequired(),
            validators.length(min=6, max=20)
        ])
    mfa = StringField('mfa', [validators.DataRequired(), validators.Length(min=10, max=20)])
    success = StringField('result')

class UserLoginForm(FlaskForm):
    uname = StringField('Username', [validators.DataRequired()])
    pword = PasswordField('Password', [validators.DataRequired()])
    mfa = StringField('mfa', [validators.DataRequired()])
    result = StringField('result')

class SpellCheckForm(FlaskForm):
    inputtext = StringField(u'inputtext', widget=TextArea())
    textout = StringField(u'textout', widget=TextArea())
    misspelled = StringField(u'misspelled', widget=TextArea())


#def get_record_numbers():
#    return RecordHistory.query()
#
class HistoryForm(FlaskForm):
    userquery = StringField('userquery')

class LoginHistoryForm(FlaskForm):
    userid = StringField('userid')

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = 'super secret key'
#app.config['WTF_CSRF_ENABLED'] = False

#Login Manager
login_manager.init_app(app)
#CSRF Protect
#csrf = CSRFProtect()
#csrf.init_app(app)


class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    user = User()
    user.id = username
    return user

@login_manager.request_loader
def request_loader(request):
    username = request.form.get('uname')
    user = User()
    user.id = username
    #user.is_authenticated = sha256_crypt.verify(password, Users[username]['password'])


@app.route('/')
@app.route('/index')
def mainpage(user=None):
    user = user
    return render_template('index.html', user=user)

#Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    DBSessionMaker = setup_db()
    session = DBSessionMaker()
    success = None
    if request.method ==  'POST' and form.validate():
        hasher = SHA256()
        pword = form.pword.data 
        hasher.update(pword.encode('utf-8'))
        uname = form.uname.data
        salt = token_hex(nbytes=16)
        hasher.update(salt.encode('utf-8'))
        passwordhash = hasher.hexdigest()
        mfa = form.mfa.data
        new_user = Users(uname=uname, pword=passwordhash, mfa=mfa, salt=salt)
        session.add(new_user)
        try:
        
            session.commit()
        except:
            form.uname.data = 'user already exists'
            success = 'failure'
            session.close()
            return render_template('register.html', form=form, success=success)
        success = "success"
        session.close()
    return render_template('register.html', form=form, success=success)

#Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = UserLoginForm() 
    result = None
    if request.method == 'POST':
       DBSessionMaker = setup_db()
       session = DBSessionMaker()
       uname = form.uname.data
       pword = form.pword.data
       mfa = form.mfa.data
       userdetails = session.query(Users).filter(Users.uname == uname).first()
       if (userdetails == None):
           result = "incorrect"
           return render_template('login.html', form=form, result=result)
       salt = userdetails.salt
       hasher = SHA256()
       hasher.update(pword.encode('utf-8'))
       hasher.update(salt.encode('utf-8'))
       passwordhash = hasher.hexdigest()
       if (passwordhash != userdetails.pword):
           result = "incorrect"
           session.close()
           return render_template('login.html', form=form, result=result)
       if (mfa != userdetails.mfa):
           result = "Two-factor failure"
           session.close()
           return render_template('login.html', form=form, result=result) 
       user = User()
       user.id = uname
       flask_login.login_user(user)
       loginrec = LoginRecord(user_id = uname, time_on = datetime.now()) 
       session.add(loginrec)
       session.commit()
       session.close()
       result = "success"
    return render_template('login.html', form=form, result=result)

#Spell Check Page
@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():    
    form = SpellCheckForm()
    textout = None
    misspelled = None
    if request.method == 'POST':
        DBSessionMaker = setup_db()
        session = DBSessionMaker()
        inputtext = form.inputtext.data
        textout = inputtext
        with open("words.txt", "w") as fo:
            fo.write(inputtext)      
        output = (check_output(["./a.out", "words.txt", "wordlist.txt"], universal_newlines=True))
        misspelled = output.replace("\n", ", ").strip().strip(',')
        user = flask_login.current_user.id
        historyrec = RecordHistory(user_id = user, query_text = inputtext, query_result = misspelled)
        session.add(historyrec)
        session.commit()
        session.close()
    response = make_response(render_template('spell_check.html', form=form, textout=textout, misspelled=misspelled))
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# Logout Page
@app.route("/logout")
@login_required
def logout():
    user = flask_login.current_user.id
    logout_user()
    DBSessionMaker = setup_db()
    session = DBSessionMaker()
    loginrec = session.query(LoginRecord).filter(LoginRecord.user_id == user).order_by(LoginRecord.time_on.desc()).first()
    loginrec.time_off = datetime.now()
    session.commit()
    session.close()
    return redirect('/login')


# Hisotry Record Page
@app.route('/history', methods=['GET', 'POST'])
@login_required
def history():
    form = HistoryForm()
    user = flask_login.current_user.id
    if (request.method == 'POST'):
        if user == 'admin':
            user = form.userquery.data
    DBSessionMaker = setup_db()
    session = DBSessionMaker()
    queries = session.query(RecordHistory).filter(RecordHistory.user_id == user)
    numqueries = queries.count()
    response = make_response(render_template('history.html', form=form, numqueries=numqueries, user = user, queries=queries))
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    session.close()
    return response


# Hisotry Record Page
@app.route('/history/query<int:queryid>')
@login_required
def history_query(queryid):
    form = HistoryForm()
    user = flask_login.current_user.id
    DBSessionMaker = setup_db()
    session = DBSessionMaker()
    queries = session.query(RecordHistory).filter(RecordHistory.record_number == queryid).first()
    if (queries.user_id != user and user != "admin"):
        queries = None
    response = make_response(render_template('query.html', form=form, queries=queries))
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    session.close()
    return response



# Hisotry Record Page
@app.route('/login_history', methods=['GET', 'POST'])
@login_required
def login_history():
    queries = None
    form = LoginHistoryForm()
    user = flask_login.current_user.id
    if (user != "admin"):
        return {"message": "not authorized"}, 401
    if (request.method == 'POST'):
        queryuser = form.userid.data
        DBSessionMaker = setup_db()
        session = DBSessionMaker()
        username = session.query(Users).filter(Users.user_id == queryuser).first()
        queries = session.query(LoginRecord).filter(LoginRecord.user_id == username.uname)
        session.close()
    response = make_response(render_template('login_history.html', form=form, user = user, queries=queries))
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
