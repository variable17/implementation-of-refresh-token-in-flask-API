import os
import functools

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity, fresh_jwt_required
    )

app = Flask(__name__)

base_dir = os.path.dirname(os.path.realpath(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(base_dir, 'data.db')

app.config['JWT_SECRET_KEY'] = 'sefybsunfco9r8wynr9c8yrf98wyc8mcf'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Dynamically defining the expiration time, default time is 15 minute for access-token
# and 30 day for the refresh token.
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta
# app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta


jwt = JWTManager(app)
db = SQLAlchemy(app)


def is_admin(f):
	@functools.wraps(f)
	def wrapped(*args, **kwargs):
		user = get_jwt_identity()
		user = User.query.filter_by(username=user).first()
		if not user.admin:
			return jsonify({'msg': 'Imposter, I got you!'}), 403
		return f(*args, **kwargs)
	return wrapped
	




# Model definition
class User(db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(30))
	password = db.Column(db.String(30))
	admin = db.Column(db.Boolean())



# Admin area
@app.route('/admin', methods=['GET'])
@jwt_required
@is_admin
def admin():
	user = get_jwt_identity()
	return jsonify({'msg': 'seems like you are the admin, {}'.format(user)}), 200



# Creating user
@app.route('/user', methods=['POST'])
def create_user():
	data = request.get_json()
	try:
		new_user = User(username=data['username'], password=data['password'], admin=data['admin'])
	except:
		return jsonify({'msg': 'Looks like you forgot a value'}), 401
	db.session.add(new_user)
	db.session.commit()

	return jsonify({'message':'New user created'}), 201



# First time login
@app.route('/login', methods=['POST'])
def login():
	username = request.json['username']
	password = request.json['password']

	user =  User.query.filter_by(username=username).first()

	if user and user.password == password:
		return jsonify({
			'access_token': create_access_token(identity=username, fresh=True),
			'refresh_token': create_refresh_token(identity=username)
			}), 200
	else:
		return jsonify({'message': 'Bad request'}), 401



# Refreshing the access_token using refresh_token
@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
	identity = get_jwt_identity()
	return jsonify({'access_token': create_access_token(identity=identity, fresh=False)}), 200



# Checking a required method
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify({'username': username}), 200



# Implement methods which requires fresh tokens i.e. password change, email change 
@app.route('/protected-fresh', methods=['GET'])
@fresh_jwt_required
def protected_fresh():
    username = get_jwt_identity()
    return jsonify({'username': username}), 200


if __name__ == '__main__':
	app.run(debug = True)