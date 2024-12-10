from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from datetime import timedelta

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['user_auth']
users_collection = db['users']

# Serve static HTML pages 
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register.html')
def register_page():
    return render_template('register.html')

@app.route('/login.html')
def login_page():
    return render_template('login.html')


@app.route('/dashboard.html')
def dashboard_page():
    return render_template('dashboard.html')

# Registration route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    role = data['role']

    if users_collection.find_one({'username': username}):
        return jsonify({'msg': 'User already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users_collection.insert_one({
        'username': username,
        'password': hashed_password,
        'role': role
    })
    return jsonify({'msg': 'User registered successfully'}), 201

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username'] 
    password = data['password']

    user = users_collection.find_one({'username': username})
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'msg': 'Invalid username or password'}), 401

    access_token = create_access_token(identity={'username': username, 'role': user['role']}, expires_delta=timedelta(hours=1))
    return jsonify({'access_token': access_token})

# Route to get user info 
@app.route('/api/user-info', methods=['GET'])
@jwt_required()                                                                                                                                      
def user_info():
    current_user = get_jwt_identity()
    return jsonify(current_user)


# Route to get all users (Admin only)
@app.route('/api/users', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'msg': 'Access denied'}), 403 

    users = users_collection.find({}, {'_id': 0, 'username': 1})
    user_list = [user['username'] for user in users]
    return jsonify(user_list)

if __name__ == '__main__':
    app.run(debug=True)


