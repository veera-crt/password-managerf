from flask import Flask, request, jsonify, session
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import random
import smtplib
from email.message import EmailMessage
from threading import Thread
from datetime import datetime, timedelta
import secrets
import os


app = Flask(__name__)
app.secret_key = ...
app.config.update(
  SESSION_COOKIE_SAMESITE='None',
  SESSION_COOKIE_SECURE=True
)

CORS(
  app,
  supports_credentials=True,
  resources={ r"/api/*": { "origins": "https://veera-crt.github.io" } }
)



# PostgreSQL config (Render)
DATABASE_URL = os.environ.get("DATABASE_URL")
conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
conn.autocommit = True



def send_otp_email(to_email, otp):
    try:
        msg = EmailMessage()
        msg.set_content(f"Your OTP is: {otp}")
        msg['Subject'] = 'CybVars OTP Verification'
        msg['From'] = "passkey2manager@gmail.com"
        msg['To'] = to_email

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login("passkey2manager@gmail.com", "eqkacwkftffzynzc")
            smtp.send_message(msg)
    except Exception as e:
        print(f"Error sending OTP email: {e}")

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data['email']
    
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    if cur.fetchone():
        return jsonify(success=False, message="Email already registered"), 409

    otp = f"{random.randint(100000, 999999)}"
    hashed = generate_password_hash(data['password'])

    try:
        cur.execute("""
            INSERT INTO users (full_name, dob, age, email, phone, password_hash, 
                            address, latitude, longitude, otp)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            data['full_name'], data['dob'], data['age'], email, 
            data['phone'], hashed, data['address'], 
            data['latitude'], data['longitude'], otp
        ))

        # Send OTP in background thread
        Thread(target=send_otp_email, args=(email, otp)).start()

        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    email = data['email']
    
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    
    if not user:
        return jsonify(success=False, message="Email not registered"), 404
    
    new_otp = f"{random.randint(100000, 999999)}"
    cur.execute("UPDATE users SET otp = %s WHERE email = %s", (new_otp, email))
    
    # Send in background
    Thread(target=send_otp_email, args=(email, new_otp)).start()
    
    return jsonify(success=True)

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data['email']
    otp_input = data['otp']

    cur = conn.cursor()
    try:
        cur.execute("SELECT otp FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user and user['otp'] == otp_input:
            cur.execute("UPDATE users SET otp_verified = TRUE WHERE email = %s", (email,))
            return jsonify(success=True)

        return jsonify(success=False, message="Invalid OTP"), 400
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500
from werkzeug.security import check_password_hash
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# AES-256 Key Setup (replace this with your secure key setup)
AES_KEY = base64.b64decode(os.environ.get("ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode()))

def encrypt_data(plain_text):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + cipher_text).decode()

def decrypt_data(enc_text):
    enc = base64.b64decode(enc_text)
    iv = enc[:16]
    cipher_text = enc[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain_text = unpadder.update(padded_data) + unpadder.finalize()
    return plain_text.decode()


# AES-256 Key Setup (32 bytes = 256 bits)
AES_KEY = base64.b64decode(os.environ.get("ENCRYPTION_KEY", base64.b64encode(os.urandom(32)).decode()))

def encrypt_data(plain_text):
    iv = os.urandom(16)  # Initialization vector for CBC mode
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + cipher_text).decode()

def decrypt_data(enc_text):
    enc = base64.b64decode(enc_text)
    iv = enc[:16]
    cipher_text = enc[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain_text = unpadder.update(padded_data) + unpadder.finalize()
    return plain_text.decode()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, otp_verified FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if not user:
        return jsonify(success=False, message="Email not registered"), 404

    if not check_password_hash(user['password_hash'], password):
        return jsonify(success=False, message="Incorrect password"), 401

    # Create session
    session.clear()
    session['user_id'] = user['id']
    session['email'] = email
    session['logged_in'] = True
    session.permanent = True

    return jsonify(success=True, verified=user['otp_verified'])

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify(success=True)

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if not session.get('logged_in'):
        return jsonify(success=False), 401
    return jsonify(success=True, email=session.get('email'))

@app.route('/api/passwords', methods=['GET'])
def get_passwords():
    if not session.get('logged_in'):
        return jsonify(success=False, message="Unauthorized"), 401

    cur = conn.cursor()
    cur.execute("""
        SELECT id, website, username, password, notes, created_at 
        FROM passwords 
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (session['user_id'],))
    passwords = cur.fetchall()
    return jsonify(success=True, passwords=passwords)

@app.route('/api/passwords', methods=['POST'])
def save_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.get_json()
    website = data.get('website')
    username = data.get('username')
    password = encrypt_data(data.get('password'))
    notes = data.get('notes')
    try:
        cur = conn.cursor()
        cur.execute('INSERT INTO passwords (user_id, website, username, password, notes, created_at) VALUES (%s, %s, %s, %s, %s, NOW())',
                    (session['user_id'], website, username, password, notes))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

def add_password():
    if not session.get('logged_in'):
        return jsonify(success=False, message="Unauthorized"), 401

    data = request.get_json()
    website = data.get('website')
    username = data.get('username')
    password = data.get('password')
    notes = data.get('notes', '')

    if not all([website, username, password]):
        return jsonify(success=False, message="Missing required fields"), 400

    cur = conn.cursor()
    cur.execute("""
        INSERT INTO passwords (user_id, website, username, password, notes)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id
    """, (session['user_id'], website, username, password, notes))
    
    new_id = cur.fetchone()['id']
    return jsonify(success=True, id=new_id)

@app.route('/api/generate-otp', methods=['POST'])
def generate_otp():
    if not session.get('logged_in'):
        return jsonify(success=False, message="Unauthorized"), 401

    otp = f"{random.randint(100000, 999999)}"
    expires_at = datetime.now() + timedelta(minutes=7)

    cur = conn.cursor()
    cur.execute("""
        UPDATE users 
        SET sensitive_action_otp = %s, otp_expires_at = %s 
        WHERE id = %s
    """, (otp, expires_at, session['user_id']))

    # Send OTP in background
    Thread(target=send_otp_email, args=(session['email'], otp)).start()

    return jsonify(success=True)

@app.route('/api/verify-action-otp', methods=['POST'])
def verify_action_otp():
    if not session.get('logged_in'):
        return jsonify(success=False, message="Unauthorized"), 401

    data = request.get_json()
    otp = data.get('otp')

    cur = conn.cursor()
    cur.execute("""
        SELECT sensitive_action_otp, otp_expires_at 
        FROM users 
        WHERE id = %s AND otp_expires_at > NOW()
    """, (session['user_id'],))
    result = cur.fetchone()

    if not result or result['sensitive_action_otp'] != otp:
        return jsonify(success=False, message="Invalid or expired OTP"), 400

    # OTP verified - create action token valid for 2 minutes
    action_token = secrets.token_urlsafe(32)
    session['action_token'] = action_token
    session['action_token_expires'] = (datetime.now() + timedelta(minutes=2)).timestamp()

    return jsonify(success=True, action_token=action_token)

@app.route("/api/passwords/<int:password_id>", methods=["PUT"])
def update_password(password_id):
    if 'user_id' not in session:
        return jsonify(success=False, message="Unauthorized"), 401

    data = request.get_json()
    website = data.get("website")
    username = data.get("username")
    password = data.get("password")
    notes = data.get("notes")
    otp = data.get("otp")

    cur = conn.cursor()
    cur.execute("SELECT sensitive_action_otp, otp_expires_at FROM users WHERE id = %s", (session['user_id'],))
    result = cur.fetchone()

    if not result or result['sensitive_action_otp'] != otp or result['otp_expires_at'] < datetime.now():
        return jsonify(success=False, message="Invalid or expired OTP"), 400

    try:
        encrypted_password = encrypt_data(password)
        cur.execute("""
            UPDATE passwords 
            SET website = %s, username = %s, password = %s, notes = %s 
            WHERE id = %s AND user_id = %s
        """, (website, username, encrypted_password, notes, password_id, session['user_id']))
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route("/api/passwords/<int:password_id>", methods=["GET"])
def get_password_by_id(password_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        cur = conn.cursor()
        cur.execute("SELECT password FROM passwords WHERE id = %s AND user_id = %s", (password_id, session['user_id']))
        row = cur.fetchone()

        if not row:
            return jsonify({"success": False, "message": "Password not found"}), 404

        decrypted_password = decrypt_data(row['password'])
        return jsonify({"success": True, "password": decrypted_password})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
@app.route("/api/passwords/<int:password_id>", methods=["DELETE"])
def delete_password(password_id):
    if 'user_id' not in session:
        return jsonify(success=False, message="Unauthorized"), 401
    
    data = request.get_json()
    action_token = data.get('action_token')
    
    # Verify action token
    if not session.get('action_token') or session.get('action_token') != action_token:
        return jsonify(success=False, message="Invalid action token"), 400
    
    # Check if token is expired
    if session.get('action_token_expires', 0) < datetime.now().timestamp():
        return jsonify(success=False, message="Action token expired"), 400
    
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM passwords WHERE id = %s AND user_id = %s", 
                   (password_id, session['user_id']))
        
        # Clear action token after use
        session.pop('action_token', None)
        session.pop('action_token_expires', None)
        
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


if __name__ == '__main__':
    app.run(debug=True)


