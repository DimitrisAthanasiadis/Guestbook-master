from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

# insantiate Flask
from sqlalchemy import text

app = Flask(__name__)
# how sqlalchemy connects to the database
# connect string configuration "dialect+driver://username:password@host:port/database"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://sql7311412:WYksFBCrMk@sql7.freemysqlhosting.net/sql7311412'
app.config['SQL_ALCHEMY_TRACK_MODIFICATIONS'] = False

# instantiate the database (?)
db = SQLAlchemy(app)


# class that is used to create the database
class Comments(db.Model):
	# db columns
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(20))
	comment = db.Column(db.String(1000))


# create a route
@app.route('/')
def index():
	# list of sql alchemy objects
	result = Comments.query.all()

	return render_template('index.html', result=result)


@app.route('/sign')
def sign():
	return render_template('sign.html')


@app.route('/process', methods=['GET', 'POST'])
def process():
	# it takes the name from the form and assigns it to the variable name
	name = request.form['name']
	# it takes the comment from the form and assigns it to the variable comment
	comment = request.form['comment']

	# instantiates the object-creates row
	signature = Comments(name=name, comment=comment)
	# adds the row
	db.session.add(signature)
	# saves the changes
	db.session.commit()

	# redirects to index so it updates
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
	com_id = request.form.args.get('id')
	query = "delete from comments where id=" + str(com_id)
	db.engine.execute(query)
	db.session.commit()

	return


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
