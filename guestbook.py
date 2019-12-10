from threading import Thread

from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import flask_login as fl
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from sqlalchemy import text, update
from wtforms.validators import DataRequired, EqualTo, ValidationError, Email
from functools import wraps
from itsdangerous import URLSafeSerializer
from flask_mail import Mail, Message

sess = Session()
app = Flask(__name__)
# how sqlalchemy connects to the database
# connect string configuration "dialect+driver://username:password@host:port/database"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:abc-123@localhost:5432/postgres'
app.config['SQL_ALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = 'super secret key'
app.config['SESSION_PERMANENT'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'jimath3@gmail.com'  # enter your email here
app.config['MAIL_DEFAULT_SENDER'] = 'jimath3@gmail.com'  # enter your email here
app.config['MAIL_PASSWORD'] = 'oqrm itmy igfv qlee'  # enter your password here
login_manager = fl.LoginManager()
login_manager.init_app(app)
csrf = CSRFProtect(app)
ts = URLSafeSerializer(app.config["SECRET_KEY"])
mail = Mail(app)

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
	email_confirmed = db.Column(db.Boolean(), default=False)
	reset_token = db.Column(db.String(767), default=None)

	def __init__(self, username, password, email):
		self.username = username
		self.set_password(password)
		self.email = email
		self.password_hash = None
		# self.is_authenticated = False
		# self.is_active = False
		self.current_user = None

	def set_password(self, password):
		self.password_hash = generate_password_hash(password)
		self.password = self.password_hash

	def check_password(self, password):
		return check_password_hash(self.password, password)

	'''def set_username(self, username):
		self.username = username
		return self.username'''


class AnonymousUser(fl.AnonymousUserMixin):
	def __init__(self):
		self.current_user = "anonymous"


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


class EmailForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])


class PasswordForm(FlaskForm):
	password = PasswordField('Password', validators=[DataRequired()])
	password2 = PasswordField(
		'Repeat Password', validators=[DataRequired(), EqualTo('password')])
	submit = SubmitField('Submit')


# custom decorator gia na dw an kapoios einai syndedemenos
def login_required(function):
	@wraps(function)
	def wrapper(*args, **kwargs):
		form = LoginForm()
		if not fl.current_user.is_authenticated:
			flash("You do not have permission to view this page", "warning")
			# abort()
			# return render_template("login.html", form=form)
			return redirect(url_for("login"))
		return function(*args, **kwargs)

	return wrapper


# custom decorator gia na dw an o xrhsths pou tsilimpourdizei einai o admin
def admin_required(function):
	@wraps(function)
	def wrapper(*args, **kwargs):
		form = LoginForm()
		if not fl.current_user.username == 'admin':
			flash("You must be admin", "warning")
			# abort()
			return redirect(url_for("login"))
		# return render_template("login.html")
		return function(*args, **kwargs)

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
	return User.query.get(str(id))


# apla den mou douleve swsta kai to ekana sxolio
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

# den doulevw me session pleon opote den xreiazetai
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


@app.route('/login', methods=['GET', 'POST'])
def login():
	'''if fl.current_user.is_authenticated:
		return redirect(url_for("index"))'''
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if not user.email_confirmed:
				flash("Account not confirmed. Go to your email to confirm the account!", "error")
				return redirect(url_for("login"))
			if not user.check_password(form.password.data):
				flash("Invalid username or password", "danger")
				return redirect(url_for('login'))
			fl.login_user(user)  # , remember=form.remember_me.data)
			flash("Logged in successfuly", "success")
			# deixnei popia tha einai h epomenh selida apo thn parousa-meta to login tha thelame thn arxikh, as poume
			# next = request.args.get('next')
			return redirect(url_for('index', current_user=fl.current_user))
		else:
			flash("User does not exist!", "warning")
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
	db.session.close()

	return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
	if fl.current_user.is_authenticated:
		flash("You are already registered", "warning")
		return redirect(url_for('index'))
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(username=request.form.get("username"), password=request.form.get("password"),
					email=request.form.get("email"))
		db.session.add(user)
		db.session.commit()

		subject = "Confirm your email"
		token = ts.dumps(user.email, salt="email-confirm-key")
		confirm_url = url_for(
			'confirm_email',
			token=token,
			_external=True
		)

		html = ""

		'''render_template(
			"confirm_email.html",
			confirm_url=confirm_url,
			form=form
		)'''

		body = "Click the link provided to confirm your email " + confirm_url

		send_email(user.email, subject, html, body)

		flash('Congratulations, you are now a registered user! Go to your email to confirm your account!', "success")
		# return redirect(url_for('login'))
		return redirect(url_for("index"))
	return render_template('register.html', title='Register', form=form)


# to ftiaxnw gia na exei asynchronh apostolh email mesw thread kai na mhn kathysterhsei to loading ths selidas-stoxoy
def async_send_email(app, msg):
	with app.app_context():
		mail.send(msg)


@app.route("/send_email/?token=<token>", methods=["GET", "POST"])
def send_email(user_email, subject, html, body):
	msg = Message(subject, recipients=[user_email])
	msg.body = body
	msg.html = html
	'''msg.html = html
	# mail.send(msg)'''
	thr = Thread(target=async_send_email, args=[app, msg])
	# flash("A confirmation link was sent to your inbox", "success")

	thr.start()


@app.route("/confirm_email/<token>", methods=['GET', 'POST'])
def confirm_email(token):
	# form = PasswordForm()
	# if form.validate_on_submit():
	email = ts.loads(token, salt="email-confirm-key")  # , max_age=86400)
	user = User.query.filter_by(email=email).first()
	if not user or user.email_confirmed == True:
		flash("Token is expired or an email has already been sent!", "warning")
		return redirect(url_for("login"))
	user.email_confirmed: bool = True
	db.session.add(user)
	db.session.commit()
	db.session.close()
	flash("Email confirmed succesfuly", "success")

	return redirect(url_for("login"))


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
	form = EmailForm()
	return render_template("forgot_password.html", form=form)


@app.route('/reset', methods=["GET", "POST"])
def reset():
	form = EmailForm()
	user = User.query.filter_by(email=form.email.data).first()
	if user:
		if user.reset_token is None:
			if form.validate_on_submit():
				subject = "Password reset requested"
				# Here we use the URLSafeTimedSerializer we created in `util` at the
				# beginning of the chapter
				token = ts.dumps(user.email, salt='recover-key')
				stmt = text("update public.user set reset_token = '" + str(token) + "' where id = " + str(user.id))
				result = db.engine.execute(stmt)

				recover_url = url_for(
					'reset_with_token',
					token=token,
					_external=True)

				html = render_template(
					'reset.html',
					recover_url=recover_url)

				body = "Password request was asked. Use the link provided" + recover_url

				# Let's assume that send_email was defined in myapp/util.py
				send_email(user.email, subject, html, body)
				flash("Recovery email sent", "success")
		else:
			flash("Token is expired or an email has already been sent!", "warning")
			return redirect(url_for("forgot_password"))
	else:
		flash("Email not found!", "dangerous")
		return redirect(url_for("forgot_password"))

	# return redirect(url_for('index'))
	return redirect(url_for('login', form=form))


@app.route('/reset/<token>', methods=["GET", "POST"])
def reset_with_token(token):
	email = ts.loads(token, salt="recover-key")
	form = PasswordForm()
	user = User.query.filter_by(email=email).first()

	if user:
		if user.reset_token is not None:
			if form.validate_on_submit():
				user.password = generate_password_hash(form.password.data)
				user.reset_token = None

				db.session.add(user)
				db.session.commit()
				db.session.close()
				flash("Password changed successfuly!", "success")

				return redirect(url_for('login'))
		else:
			flash("Token is expired!", "warning")
			return redirect(url_for("login"))
	return render_template('reset_with_token.html', form=form, token=token)


@app.route("/logout")
@login_required
def logout():
	fl.logout_user()
	return redirect(url_for("index"))


@app.route('/edit_com/', methods=['GET', 'POST'])
@login_required
def edit_com():
	form = EditComForm()
	com_id = request.args.get('com_id')
	if com_id is None:
		flash("There was no comment id", "danger")
		return redirect(url_for('index'))
	session['com_id'] = com_id
	query = text("select * from comments where id=" + str(com_id))
	comment = Comments.query.filter_by(id=com_id).first()

	return render_template("edit.html", name=comment.name, comment=comment.comment, id=comment.id, form=form)


@app.route("/edit_com/edit_com_process", methods=['GET', 'POST'])
@login_required
def edit_com_process():
	# com_id = request.form['com_id']
	com_id = request.form['com_id']
	if com_id is None:
		flash("There was no comment id", "danger")
		return redirect(url_for("index"))
	com_cont = request.form['comment']

	comment = Comments.query.filter_by(id=com_id).first()
	comment.comment = com_cont

	return redirect(url_for('index'))


# made with redirect method
@app.route('/delete_red/', methods=['GET', 'POST'])
@login_required
@admin_required
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
@login_required
def delete_ajax():
	com_id = request.args.get('com_id')
	comment = Comments.query.filter_by(id=com_id).first()
	if comment is None:
		flash("No comment id provided", "danger")
		return redirect(url_for("index"))
	db.session.query(Comments).filter(Comments.id == com_id).delete(synchronize_session='evaluate')
	# query = "delete from public.comments where id=" + str(com_id)
	# session.pop("comment", None)
	# db.engine.execute(query)
	db.session.commit()
	# db.session.close()

	return jsonify(status="success")

@app.route('/delete_coms_ajax', methods=['GET', 'POST'])
@admin_required
def delete_coms_ajax():
	sel_comments = request.args.getlist("sel_comments[]")
	if len(sel_comments) == 0:
		flash("No comments selected", "error")
		return redirect(url_for("index"))
	else:
		for i in sel_comments:
			comment = Comments.query.filter_by(id=int(i)).first()
			if comment is None:
				flash("No comment id provided", "danger")
				return redirect(url_for("index"))
			db.session.query(Comments).filter(Comments.id == int(i)).delete(synchronize_session='evaluate')
			db.session.commit()
	return jsonify(status="success")

@app.route('/delete_user_ajax', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_user_ajax():
	u_id = request.args.get('u_id')
	user = User.query.filter_by(id=u_id).first()
	if user is None:
		flash("User not found", "error")
		return redirect(url_for("index"))
	# query = "delete from public.user where id=" + str(u_id)
	# db.engine.execute(query)
	db.session.query(User).filter(User.id == u_id).delete(synchronize_session='evaluate')
	db.session.commit()
	# db.session.close()

	return jsonify(status="success")


@app.route('/users_list', methods=['GET', 'POST'])
@login_required
@admin_required
def users_list():
	if fl.current_user is not None:
		if fl.current_user.username == 'admin':
			# return redirect(url_for('users_list'))
			return display_users()


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
	return render_template("profile.html")


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
