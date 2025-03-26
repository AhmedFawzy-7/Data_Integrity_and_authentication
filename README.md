# Data Integrity Task - Flask & MongoDB

## Overview
This project is a **Flask-based REST API** that integrates **MongoDB** for data storage. It includes **user authentication with JWT & 2FA**, along with CRUD operations for product management.

## Features
- **User Authentication**
  - Signup with password hashing
  - Login with password verification
  - Two-Factor Authentication (2FA) using TOTP & QR codes
  - JWT-based authentication
- **Product Management**
  - Create, read, update, and delete products (CRUD)
- **MongoDB as Database**
- **RESTful API** endpoints

## Prerequisites
- **Python 3.8+**
- **MongoDB** installed and running
- **Postman** or any API testing tool
- Required Python Packages:
  ```sh
  pip install flask flask-bcrypt flask-jwt-extended flask-pymongo pyotp qrcode
  ```

## Setup Instructions

### 1. Start MongoDB
Ensure MongoDB is running on `localhost:27017`. You can start it using:
```sh
mongod --dbpath /path/to/db
```

### 2. Run Flask Application
```sh
python app.py
```

### 3. Test API with Postman
Use Postman to test the endpoints.

#### User Authentication
- **Signup** (`POST /signup`)
- **Login** (`POST /login`)
- **Verify 2FA** (`POST /verify-2fa`)
- **Generate QR Code for 2FA** (`GET /generate-2fa/<username>`)

#### Product Management (Requires JWT Token)
- **Create Product** (`POST /products`)
- **Get All Products** (`GET /products`)
- **Get Product by ID** (`GET /products/<pid>`)
- **Update Product** (`PUT /products/<pid>`)
- **Delete Product** (`DELETE /products/<pid>`)

## Notes
- Ensure you replace `your_secret_key` in the code with a secure key.
- JWT token must be included in the **Authorization Header** as `Bearer <token>`.

## Author
Ahmed

---
🚀 Happy Coding!

