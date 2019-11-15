from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_bcrypt import Bcrypt

# insantiate Flask
from sqlalchemy import text

sess = Session()
app = Flask(__name__)
# how sqlalchemy connects to the database
# connect string configuration "dialect+driver://username:password@host:port/database"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://sql7311412:WYksFBCrMk@sql7.freemysqlhosting.net/sql7311412'
app.config['SQL_ALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = 'super secret key'
app.config['SESSION_PERMANENT'] = True

# instantiate the database (?)
db = SQLAlchemy(app)
logged_in = False


# class that is used to create the database
class Comments(db.Model):
	# db columns
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(20))
	comment = db.Column(db.String(1000))


class Users(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20))
	password = db.Column(db.String(100))


# create a route
@app.route('/')
def index():
	# list of sql alchemy objects
	result = Comments.query.all()

	return render_template('index.html', result=result)


@app.route('/sign')
def sign():
	return render_template('sign.html')


@app.route('/comment_process', methods=['GET', 'POST'])
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


@app.route('/login_process', methods=['POST'])
def login_process():
	error = None
	username = request.form.get('username')
	password = request.form.get('password')
	# exists = bool(Users.query.filter_by(username=username).first())
	exists = db.session.query(db.session.query(Users).filter_by(username=username).exists()).scalar()

	if exists == True:
		logged_in = True
		session['username'] = username
		session['password'] = password
		session['logged_in'] = logged_in
		flash("Successful login", "success")
		return redirect(url_for("index"))
	else:
		flash("Invalid credentials", "error")

	return redirect(url_for("login"))


@app.route('/login', methods=['GET', 'POST'])
def login():
	return render_template('login.html')


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
	return render_template('sign_up.html')


@app.route('/sign_up_process', methods=['POST'])
def sign_up_process():
	username = request.form['username']
	password = request.form['password']
	exists = db.session.query(db.session.query(Users).filter_by(username=username).exists()).scalar()


	if exists == True:
		flash("You cannot use this username", "error")
		return redirect(url_for('sign_up'))

	user = Users(username=username, password=password)
	db.session.add(user)
	db.session.commit()
	session['logged_in'] = True
	session['username'] = username
	session['password'] = password

	return redirect(url_for('index'))


@app.route("/logout")
def logout():
	session["logged_in"] = False
	session.pop("username", None)
	session.pop("password", None)

	return redirect(url_for('index'))

@app.route('/edit_com/', methods=['GET', 'POST'])
def edit_com():
	com_id = request.args.get('com_id')
	session['com_id'] = com_id
	query = text("select * from comments where id=" + str(com_id))
	result = db.engine.execute(query)
	db.engine.execute(query)
	db.session.commit()

	# return redirect(url_for('index'))
	return render_template("edit.html", result=result)


@app.route("/edit_com/edit_com_process", methods=['GET', 'POST'])
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
def delete_user_ajax():
	u_id = request.args.get('u_id')
	query = "delete from users where id=" + str(u_id)
	db.engine.execute(query)
	db.session.commit()

	return jsonify(status="success")

@app.route('/users_list', methods=['GET', 'POST'])
def users_list():
	if session.get('username') is not None:
		if session['username'] == 'admin':
			# return redirect(url_for('users_list'))
			return display_users()
		else:
			return render_template('you_are_not_admin.html')
	else:
		return render_template("login_first.html")

@app.route("/display_users", methods=['GET', 'POST'])
def display_users():
	if session.get('username') is not None:
		if session.get('username') == 'admin':
			result = Users.query.all()
			return render_template("users.html", result=result)
		else:
			return render_template("you_are_not_admin.html")
	else:
		return render_template("login_first.html")


@app.route('/home', methods=['GET', 'POST'])
def home():
	links = ['https://www.google.gr', 'https://www.youtube.com', 'https://www.facebook.com', 'https://www.twitter.com']
	# it searches for a file in the default path "./templates/FILE_NAME" to open it
	# the render_template function does the searching job
	return render_template('example.html', links=links)


# <VARIABLE_NAME> is a variable that is passed through the URL bar
# @app.route('/home/<place>')
# def home(place):
# return '<h1>You are on the  ' + place + ' page</h1>'

# if i call it from command line (which i do), then debug mode is on
if __name__ == '__main__':
	app.run(debug=True)







''' from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

hash1 = bcrypt.generate_password_hash('secret')
hash2 = bcrypt.generate_password_hash('secret')

hash1 == hash2 # False - check out the hashes, they'll have different values!
hash3 = bcrypt.generate_password_hash('secret', 17) # the second argument lets us increase/decrease the work factor. Default value is 12. '''