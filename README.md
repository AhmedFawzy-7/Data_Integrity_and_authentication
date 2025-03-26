# 📌 Data Integrity Task - Flask & MongoDB API

## 📜 Project Description
This project is a RESTful API built with Flask and MongoDB for handling user authentication with 2FA and product management. The API allows user registration, login, 2FA verification, and CRUD operations on products.

## 🛠️ Setup Instructions

### 1️⃣ Prerequisites
- Python 3.x 🐍
- MongoDB installed and running on `localhost:27017` 🗄️
- Postman or any API testing tool 🌍

### 2️⃣ Install Dependencies
Run the following command to install required packages:
```bash
pip install flask flask_bcrypt flask_jwt_extended flask_pymongo pyotp qrcode pillow
```

### 3️⃣ Run MongoDB (if not already running)
If you're using a local MongoDB instance, start it with:
```bash
mongod
```

### 4️⃣ Run the Flask Application
```bash
python app.py
```

## 🔑 Authentication Endpoints

### 🚀 User Signup
**Endpoint:** `POST /signup`
```json
{
  "name": "Ahmed",
  "username": "Ahmed123",
  "password": "securepassword"
}
```

### 🔐 User Login
**Endpoint:** `POST /login`
```json
{
  "username": "Ahmed123",
  "password": "securepassword"
}
```

### 📲 Generate 2FA QR Code
**Endpoint:** `GET /generate-2fa/{username}`

### ✅ Verify 2FA Code
**Endpoint:** `POST /verify-2fa`
```json
{
  "username": "Ahmed123",
  "code": "123456"
}
```

## 📦 Product Management Endpoints

### ➕ Create Product
**Endpoint:** `POST /products`
```json
{
  "pname": "Laptop",
  "description": "Gaming Laptop",
  "price": 1200.99,
  "stock": 10
}
```

### 📋 Get All Products
**Endpoint:** `GET /products`

### 🔍 Get a Single Product
**Endpoint:** `GET /products/{pid}`

### ✏️ Update a Product
**Endpoint:** `PUT /products/{pid}`
```json
{
  "price": 999.99
}
```

### ❌ Delete a Product
**Endpoint:** `DELETE /products/{pid}`

## 🎯 Notes
- Use the generated JWT token in the `Authorization` header (`Bearer <token>`) for protected routes.
- Ensure MongoDB is running before making API calls.
- Scan the QR code with a 2FA authenticator app (Google Authenticator, Authy) to generate the 2FA code.

🚀 Happy Coding! 💻🔥

