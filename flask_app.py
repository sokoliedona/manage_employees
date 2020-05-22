# This program creates a web application for an Manager who can create his own account and log in or log out.
# He can perform CRUD operations for his Employees' Information
# Like: create(add) new Employee with his name,surname,email, phone number and ID card and store their CV in the static folder inside the project
# The manager can update and delete their informations and search for any employee in the database

from flask import Flask, redirect, url_for, render_template, request
from flask_login import LoginManager, UserMixin,  current_user, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from pony.orm import Database, Required, Optional, db_session, select, PrimaryKey
import keygen
from forms import LoginForm
from werkzeug.utils import secure_filename
import os



app = Flask(__name__)
app.secret_key = keygen.generate()
login = LoginManager(app)
login.login_view = 'login'

db = Database()

class User(UserMixin, db.Entity):

    username = Required(str, unique=True)
    password_hash = Optional(str)

    @db_session
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    @db_session
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)

class Employee(db.Entity):
    id = PrimaryKey(int, auto = True)
    name = Required(str)
    surname = Required(str)
    email = Required(str)
    phone = Required(str)
    id_card = Required(str)


db.bind(provider='sqlite', filename='mydb', create_db=True)
db.generate_mapping(create_tables=True)


@login.user_loader
@db_session
def load_user(id):
    return User.get(id=int(id))


@app.route('/')
@login_required
def index():
    return redirect (url_for('manage'))
    return render_template('index.html', NAME=current_user.username)



app.config['UPLOAD_FOLDER'] = "/home/Edonaaaaa1096/finalprojecticts/static"
app.config['ALLOWED_EXTENSIONS'] = ["PDF"]

def allowed_file(filename):
    if not "." in filename:
        return False
    ext = filename.rsplit(".",1)[1]

    if ext.upper() in app.config['ALLOWED_EXTENSIONS'] :
        return True
    else :
        return False


@app.route('/upload', methods = ['GET', 'POST'])
def upload():

    if request.method == 'POST':

        if request.files:

            f = request.files['file']

            if not allowed_file(f.filename):
                print("This file should be PDF")
                response = redirect(request.url)
                return response
            else:
                filename = secure_filename(f.filename)
                #f.save(filename)

                f.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))

            print ("File saved")
            return redirect (url_for('manage'))

    return render_template("upload.html")

@app.route('/manage', methods = ['GET', 'POST'])
#@login_required
def manage():

    if request.method == 'GET' :
        searchtext = request.args.get('SearchText','')
        result = list (select(p for p in Employee if searchtext.upper() in p.name.upper()))

        return render_template('index.html', EMPLOYEE = result)

    elif request.method == 'POST' :
        name = request.form.get('name')
        surname = request.form.get('surname')
        email = request.form.get('email')
        phone = request.form.get('phone')
        id_card = request.form.get('id_card')

        Employee(name = name, surname = surname, email = email, phone=phone, id_card = id_card)

        return redirect(url_for('upload'))

    return render_template('index.html', NAME=current_user.username)



@app.route('/delete/<id>', methods = ['GET', 'POST'])
@db_session
def delete(id):

    if Employee[id] :
        Employee[id].delete()
    return redirect(url_for('manage'))


@app.route('/manage/<id>', methods = ['GET', 'POST'])
@db_session
def update(id):

    if request.method == 'POST' :

        if Employee[id] :

                name = request.form.get('name')
                surname = request.form.get('surname')
                email = request.form.get('email')
                phone = request.form.get('phone')
                id_card = request.form.get('id_card')


                Employee[id].set(name=name, surname=surname, email=email, phone=phone, id_card=id_card)

                return redirect(url_for('manage'))

    elif request.method == 'GET' :

        if Employee[id] :

            return render_template('employee_update.html',EMPLOYEE = Employee[id])


@app.route('/login', methods=['GET', 'POST'])
@db_session
def login():

    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.get(username=form.username.data)

        if user is None or not user.check_password(form.password.data):
            return redirect(url_for('login'))

        login_user(user)  # remember=form.remember_me.data)
        return redirect(url_for('index'))

    return render_template('login.html', title='Sign In', form=form)

@app.route('/new_user', methods=['GET', 'POST'])
@db_session
def new_user_form():
    if request.method == 'GET':
        return render_template('newuserform.html')

    elif request.method == 'POST':
        data = request.form.to_dict()

        u = User(username=data['username'])
        u.set_password(data['password'])

        return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    if request.method == 'GET' :
        logout_user()
        return redirect(url_for('index'))


