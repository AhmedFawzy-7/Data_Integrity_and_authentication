from flask import Flask, request, jsonify, send_file
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_pymongo import PyMongo
import pyotp
import qrcode
import io
import datetime
import os
from bson import ObjectId

app = Flask(__name__)

# MongoDB Configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/AppDB"
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Set a secret key

# ----------------------- Authentication Routes -----------------------

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if not all(k in data for k in ['name', 'username', 'password']):
        return jsonify({'error': 'Missing fields'}), 400

    if mongo.db.users.find_one({'username': data['username']}):
        return jsonify({'error': 'Username already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    secret = pyotp.random_base32()
    new_user = {
        "name": data['name'],
        "username": data['username'],
        "password": hashed_password,
        "secret": secret
    }
    mongo.db.users.insert_one(new_user)

    return jsonify({'message': 'User registered successfully, please set up 2FA'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not all(k in data for k in ['username', 'password']):
        return jsonify({'error': 'Missing fields'}), 400

    user = mongo.db.users.find_one({'username': data['username']})
    if not user or not bcrypt.check_password_hash(user['password'], data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

    return jsonify({'message': 'Enter 2FA code', 'username': user['username']}), 200

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    username = data.get('username')
    user_code = data.get('code')

    user = mongo.db.users.find_one({'username': username})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    totp = pyotp.TOTP(user['secret'])
    if totp.verify(user_code):
        token = create_access_token(identity=str(user['_id']), expires_delta=datetime.timedelta(minutes=10))
        return jsonify({'message': '2FA verified successfully', 'token': token})
    else:
        return jsonify({'error': 'Invalid or expired code'}), 401

@app.route('/generate-2fa/<username>', methods=['GET'])
def generate_2fa(username):
    user = mongo.db.users.find_one({'username': username})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    uri = pyotp.totp.TOTP(user['secret']).provisioning_uri(name=username, issuer_name='Data_Integrity_Section_2FA')
    qr = qrcode.make(uri)
    img = io.BytesIO()
    qr.save(img)
    img.seek(0)

    return send_file(img, mimetype='image/png')

# ----------------------- Product Operations -----------------------

@app.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    data = request.json
    if not all(k in data for k in ['pname', 'price', 'stock']):
        return jsonify({'error': 'Missing fields'}), 400

    new_product = {
        "pname": data['pname'],
        "description": data.get('description', ''),
        "price": float(data['price']),
        "stock": int(data['stock']),
        "created_at": datetime.datetime.utcnow()
    }
    inserted_product = mongo.db.products.insert_one(new_product)
    new_product['_id'] = str(inserted_product.inserted_id)  # Convert ObjectId to string
    return jsonify(new_product), 201

@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    products = list(mongo.db.products.find())
    for product in products:
        product['_id'] = str(product['_id'])  # Convert ObjectId to string
    return jsonify(products)

@app.route('/products/<string:pid>', methods=['GET'])
@jwt_required()
def get_product(pid):
    product = mongo.db.products.find_one({"_id": ObjectId(pid)})
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    product['_id'] = str(product['_id'])
    return jsonify(product)

@app.route('/products/<string:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    data = request.json
    update_fields = {}

    if 'pname' in data:
        update_fields['pname'] = data['pname']
    if 'description' in data:
        update_fields['description'] = data['description']
    if 'price' in data:
        update_fields['price'] = float(data['price'])
    if 'stock' in data:
        update_fields['stock'] = int(data['stock'])

    result = mongo.db.products.update_one({"_id": ObjectId(pid)}, {"$set": update_fields})
    if result.matched_count == 0:
        return jsonify({'error': 'Product not found'}), 404

    return jsonify({'message': 'Product updated successfully'})

@app.route('/products/<string:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    result = mongo.db.products.delete_one({"_id": ObjectId(pid)})
    if result.deleted_count == 0:
        return jsonify({'error': 'Product not found'}), 404

    return jsonify({'message': 'Product deleted'}), 200

# ----------------------- Run Application -----------------------

if __name__ == '__main__':
    app.run(debug=True)
