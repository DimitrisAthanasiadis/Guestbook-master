from os import abort

from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import flask_login as fl
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
# insantiate Flask
from sqlalchemy import text
from wtforms.validators import DataRequired, EqualTo, ValidationError, Email
from functools import wraps

sess = Session()
app = Flask(__name__)
# how sqlalchemy connects to the database
# connect string configuration "dialect+driver://username:password@host:port/database"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://sql7311412:WYksFBCrMk@sql7.freemysqlhosting.net/sql7311412'
app.config['SQL_ALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = 'super secret key'
app.config['SESSION_PERMANENT'] = True
login_manager = fl.LoginManager()
login_manager.init_app(app)
csrf = CSRFProtect(app)

# instantiate the database (?)
db = SQLAlchemy(app)
logged_in = False


# class that is used to create the database
class Comments(db.Model):
	# db columns
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(20))
	comment = db.Column(db.String(1000))


'''class Users(db.Model, fl.UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    password = db.Column(db.String(100))'''


class User(db.Model, fl.UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20))
	password = db.Column(db.String(100))
	email = db.Column(db.String(100))

	def __init__(self, username, password, email):
		self.username = username
		self.password = password
		self.email = email
		self.password_hash = None
		# self.is_authenticated = False
		# self.is_active = False
		self.current_user = None

	def set_password(self, password):
		self.password_hash = generate_password_hash(password)
		return self.password_hash

	def check_password(self, password):
		return check_password_hash(self.set_password(password), password)

	'''def set_username(self, username):
		self.username = username
		return self.username'''


class LoginForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	submit = SubmitField('Submit')


class EditComForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	comment = StringField('Comment')
	submit = SubmitField('Submit')


class RegistrationForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Password', validators=[DataRequired()])
	password2 = PasswordField(
		'Repeat Password', validators=[DataRequired(), EqualTo('password')])
	submit = SubmitField('Register')

	def validate_username(self, username):
		user = User.query.filter_by(username=username.data).first()
		if user is not None:
			raise ValidationError('Please use a different username.')

	def validate_email(self, email):
		user = User.query.filter_by(email=email.data).first()
		if user is not None:
			raise ValidationError('Please use a different email address.')



# custom decorator gia na dw an kapoios einai syndedemenos
def login_required(function):
	@wraps(function)
	def wrapper():
		form = LoginForm()
		if not fl.current_user.is_authenticated:
			flash("You do not have permission to view this page", "warning")
			# abort()
		return render_template("login.html", form=form)
	return wrapper

# custom decorator gia na dw an o xrhsths pou tsilimpourdizei einai o admin
def admin_required(function):
	@wraps(function)
	def wrapper():
		form = LoginForm()
		if not fl.current_user.is_authenticated or fl.current_user.username == 'admin':
			flash("You do not have permission to view this page", "warning")
			# abort()
		return render_template("login.html", form=form)
	return wrapper


# create a route
@app.route('/')
def index():
	# list of sql alchemy objects
	result = Comments.query.all()

	return render_template('index.html', result=result)


@app.route('/sign')
@login_required
def sign():
	form = EditComForm()
	return render_template('sign.html', form=form)


@app.route('/comment_process', methods=['GET', 'POST'])
@login_required
def comment_process():
	# it takes the name from the form and assigns it to the variable name
	name = request.form['name']
	# it takes the comment from the form and assigns it to the variable comment
	comment = request.form['comment']
	session['com_cont'] = comment

	# instantiates the object-creates row
	signature = Comments(name=name, comment=comment)
	# adds the row
	db.session.add(signature)
	# saves the changes
	db.session.commit()

	# redirects to index so it updates
	return redirect(url_for('index'))


@login_manager.user_loader
def user_loader(id):
	'''exists = db.session.query(db.session.query(Users).filter_by(username=username).exists()).scalar()

	if not exists:
		#flash("Invalid credentials", "error")
		return

	user = Users()
	user.username = username'''
	return User.query.get(str(id))


'''@login_manager.request_loader
def request_loader(request):
	username = request.form.get('username')
	exists = db.session.query(db.session.query(User).filter_by(username=username).exists()).scalar()

	if not exists:
		# flash("Invalid credentials", "error")
		return

	user = User()
	user.username = fl.current_user.username
	query = text("select password from users where username='" + str(username)) + "'"
	result = db.engine.execute(query)
	db.session.commit()
	user.is_authenticated = request.form['password'] == result

	return user'''


@app.route('/login_process', methods=['POST'])
def login_process():
	error = None
	username = request.form.get('username')
	password = request.form.get('password')
	password_hash = check_password_hash(password)
	# exists = bool(Users.query.filter_by(username=username).first())
	exists = db.session.query(
		db.session.query(User).filter_by(username=username, password=password_hash).exists()).first()

	# if exists == True:
	logged_in = True
	session['username'] = username
	session['password'] = password_hash
	session['logged_in'] = logged_in
	user = User()
	user.username = username
	fl.login_user(user)
	flash("Successful login", "success")

	return redirect(url_for("index"))
	'''else:
		flash("Invalid credentials", "error")'''


# return redirect(url_for("login"))


@app.route('/login', methods=['GET', 'POST'])
def login():
	'''if fl.current_user.is_authenticated:
		return redirect(url_for("index"))'''
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user is None or not user.check_password(form.password.data):
			flash("Invalid username or password")
			return redirect(url_for('login'))
		fl.login_user(user)  # , remember=form.remember_me.data)
		flash("Logged in successfuly", "success")
		# deixnei popia tha einai h epomenh selida apo thn parousa-meta to login tha thelame thn arxikh, as poume
		# next = request.args.get('next')
		return redirect(url_for('index', current_user=fl.current_user))

	return render_template('login.html', title='Login', form=form)


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
	return render_template('sign_up.html')


@app.route('/sign_up_process', methods=['POST'])
def sign_up_process():
	username = request.form['username']
	password = request.form['password']
	password_hash = generate_password_hash(password)
	exists = db.session.query(db.session.query(User).filter_by(username=username).exists()).scalar()

	if exists == True:
		flash("You cannot use this username", "error")
		return redirect(url_for('sign_up'))

	user = User(username=username, password=password_hash)
	db.session.add(user)
	db.session.commit()
	session['logged_in'] = True
	session['username'] = username
	session['password'] = password_hash

	return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
	if fl.current_user.is_authenticated:
		return redirect(url_for('index'))
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(username=form.username.data, password=form.password.data, email=form.email.data)
		# user.set_username(form.username.data)
		user.set_password(form.password.data)
		db.session.add(user)
		db.session.commit()
		flash('Congratulations, you are now a registered user!')
		return redirect(url_for('login'))
	return render_template('register.html', title='Register', form=form)


@app.route("/logout")
def logout():
	fl.logout_user()
	return redirect(url_for("index"))

	return redirect(url_for('index'))


@app.route('/edit_com/', methods=['GET', 'POST'])
@login_required
def edit_com():
	form = EditComForm()
	com_id = request.args.get('com_id')
	session['com_id'] = com_id
	query = text("select * from comments where id=" + str(com_id))
	result = db.engine.execute(query)
	db.engine.execute(query)
	db.session.commit()

	# return redirect(url_for('index'))
	return render_template("edit.html", result=result, form=form)


@app.route("/edit_com/edit_com_process", methods=['GET', 'POST'])
@login_required
def edit_com_process():
	# com_id = request.form['com_id']
	com_id = request.form['com_id']
	com_cont = request.form['comment']

	query = text("update comments set comment = '" + str(com_cont) + "' where id = " + str(com_id))
	db.engine.execute(query)
	db.session.commit()

	return redirect(url_for('index'))


# made with redirect method
@app.route('/delete_red/', methods=['GET', 'POST'])
def delete_red():
	# i should use AJAX so that i do not redirect
	if request.method == 'POST':
		comId = request.args.get('id')
		query = text("delete from comments where id=" + str(comId))
		db.engine.execute(query)
		db.session.commit()

		return redirect(url_for('index'))
	else:
		return render_template('index.html')


# uses AJAX to delete
@app.route('/delete_ajax', methods=['GET', 'POST'])
def delete_ajax():
	com_id = request.args.get('com_id')
	query = "delete from comments where id=" + str(com_id)
	session.pop("comment", None)
	db.engine.execute(query)
	db.session.commit()

	return jsonify(status="success")


# return redirect(url_for('index'))

@app.route('/delete_user_ajax', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_user_ajax():
	u_id = request.args.get('u_id')
	query = "delete from users where id=" + str(u_id)
	db.engine.execute(query)
	db.session.commit()

	return jsonify(status="success")


@app.route('/users_list', methods=['GET', 'POST'])
@login_required
@admin_required
def users_list():
	if fl.current_user is not None:
		if fl.current_user.username == 'admin':
			# return redirect(url_for('users_list'))
			return display_users()
		'''else:
			return render_template('you_are_not_admin.html')
	else:
		return render_template("login_first.html")'''


@app.route("/display_users", methods=['GET', 'POST'])
@login_required
@admin_required
def display_users():
	if fl.current_user is not None:
		if fl.current_user.username == 'admin':
			result = User.query.all()
			return render_template("users.html", result=result)
		'''else:
			return render_template("you_are_not_admin.html")
	else:
		return render_template("login_first.html")'''


@app.route("/profile/", methods=['GET', 'POST'])
@login_required
def profile():
	if session.get('username') is not None:
		username = request.args.get('user')
		query = "select * from users where username='" + str(username) + "'"
		db.engine.execute(query)
		db.session.commit()

		return render_template("profile.html", result=query)
	else:
		return render_template("login_first.html")


@app.route('/home', methods=['GET', 'POST'])
def home():
	links = ['https://www.google.gr', 'https://www.youtube.com', 'https://www.facebook.com', 'https://www.twitter.com']
	# it searches for a file in the default path "./templates/FILE_NAME" to open it
	# the render_template function does the searching job
	return render_template('example.html', links=links)


# <VARIABLE_NAME> is a variable that is passed through the URL bar
# @models.route('/home/<place>')
# def home(place):
# return '<h1>You are on the  ' + place + ' page</h1>'

# if i call it from command line (which i do), then debug mode is on
if __name__ == '__main__':
	app.run(debug=True)

# test comment

''' from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

hash1 = bcrypt.generate_password_hash('secret')
hash2 = bcrypt.generate_password_hash('secret')

hash1 == hash2 # False - check out the hashes, they'll have different values!
hash3 = bcrypt.generate_password_hash('secret', 17) # the second argument lets us increase/decrease the work factor. Default value is 12. '''
