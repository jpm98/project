from flask import Flask, request, jsonify, render_template
from werkzeug.security import check_password_hash, generate_password_hash
from flask_cors import CORS
from datetime import datetime, timedelta
import mysql.connector
import smtplib, random
from email.mime.text import MIMEText
import os

app = Flask(__name__)
CORS(app)

db_config = {
    'host': os.environ.get('DB_HOST'),
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASSWORD'),
    'database': os.environ.get('DB_NAME'),
    'port': int(os.environ.get('DB_PORT', 3306))
}

otp_store = {}

def get_db_connection():
    return mysql.connector.connect(**db_config)

def send_email(to_email, otp):
    msg = MIMEText(f"Your password reset OTP is: {otp}")
    msg['Subject'] = "AFIF & JP Password Reset OTP"
    msg['From'] = "your_email@gmail.com"
    msg['To'] = to_email

    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login("your_email@gmail.com", "YOUR_APP_PASSWORD")
    server.send_message(msg)
    server.quit()
@app.route("/")
def login():
    return render_template("login.html")

# --- 1) Send OTP ---
@app.route('/send-reset-otp', methods=['POST'])
def send_reset_otp():
    data = request.json or {}
    email = data.get('email')
    if not email:
        return jsonify({'message': 'Email required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({'message': 'Email not found'}), 404

    otp = f"{random.randint(100000, 999999)}"
    otp_store[email] = {
        'otp': otp,
        'expires': datetime.now() + timedelta(minutes=10)
    }
    send_email(email, otp)
    return jsonify({'message': 'OTP sent'}), 200

# --- 2) Verify OTP ---
@app.route('/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    data = request.json or {}
    email = data.get('email')
    otp = data.get('otp')
    record = otp_store.get(email)

    if not record or record['expires'] < datetime.now() or record['otp'] != otp:
        return jsonify({'message': 'Invalid or expired OTP'}), 400

    return jsonify({'message': 'OTP verified'}), 200

# --- 3) Reset Password ---
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    new_password = data.get('password')

    if not email or not new_password:
        return jsonify({'message': 'Missing email or password'}), 400

    record = otp_store.get(email)
    if not record or record['expires'] < datetime.now():
        return jsonify({'message': 'OTP not verified or expired'}), 401

    hashed_password = generate_password_hash(new_password)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
    conn.commit()
    cursor.close()
    conn.close()

    otp_store.pop(email, None)
    return jsonify({'message': 'Password reset successful'}), 200

# --- Login ---
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and check_password_hash(user['password'], password):
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

# --- Signup ---
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password or not email:
        return jsonify({'message': 'Missing required fields'}), 400

    hashed_password = generate_password_hash(password)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)",
            (username, hashed_password, email)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'message': 'User created'}), 201
    except mysql.connector.IntegrityError:
        return jsonify({'message': 'Username or email already exists'}), 409

# --- Forgot Username ---
@app.route('/forgot-username', methods=['POST'])
def forgot_username():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT username FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user:
        return jsonify({'username': user['username']})
    else:
        return jsonify({'message': 'Email not found'}), 404

# --- Run the App ---
if __name__ == '__main__':
    app.run(debug=True)
