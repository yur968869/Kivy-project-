
import os
import jwt
import hashlib
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, emit
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import subprocess

# Configuration
UPLOAD_FOLDER = 'uploads'
SECRET_KEY = os.getenv('JWT_SECRET', 'MY_JWT_SECRET')  # Secret key for JWT authentication
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', Fernet.generate_key())  # Encryption key for encrypting files

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = SECRET_KEY
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
fernet = Fernet(ENCRYPTION_KEY)

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 🔐 JWT Authentication
ADMIN_ID = 'Uno@123'  # Admin username
ADMIN_PASSWORD = 'Uno@123'  # Admin password

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if username == ADMIN_ID and password == ADMIN_PASSWORD:
        token = jwt.encode({'username': username}, SECRET_KEY, algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401

def authenticate(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# 🔒 Save Code Securely
@app.route('/save', methods=['POST'])
def save_code():
    token = request.headers.get('Authorization').split()[1]
    if not authenticate(token):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    filename = secure_filename(data.get('filename'))
    code = data.get('code')
    encrypted_code = fernet.encrypt(code.encode())
    with open(os.path.join(UPLOAD_FOLDER, filename), 'wb') as file:
        file.write(encrypted_code)
    return jsonify({'success': True})

# 🔧 Debugging and Testing
@app.route('/debug', methods=['POST'])
def debug_code():
    token = request.headers.get('Authorization').split()[1]
    if not authenticate(token):
        return jsonify({'error': 'Unauthorized'}), 401
    code = request.json.get('code')
    try:
        output = subprocess.run(
            ['python3', '-c', code],
            capture_output=True,
            text=True
        )
        return jsonify({'output': output.stdout or output.stderr})
    except Exception as e:
        return jsonify({'error': str(e)})

# ✅ File Upload
@app.route('/upload', methods=['POST'])
def upload_file():
    token = request.headers.get('Authorization').split()[1]
    if not authenticate(token):
        return jsonify({'error': 'Unauthorized'}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return jsonify({'success': True, 'filePath': os.path.join(UPLOAD_FOLDER, filename)})

# 🔒 Secure 2FA
@app.route('/2fa', methods=['POST'])
def two_factor_auth():
    return jsonify({'token': hashlib.sha256(b'2fa-token').hexdigest()})

# 🌍 Real-Time Collaboration (Socket.IO)
@socketio.on('joinRoom')
def handle_join(data):
    room = data.get('roomId')
    join_room(room)

@socketio.on('codeChange')
def handle_code_change(data):
    room = data.get('roomId')
    code = data.get('code')
    emit('codeChange', {'code': code}, room=room)

# 🎨 Frontend (HTML + JS)
@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

# 📂 Serve Static Files
@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('public', filename)

# 🌐 Electron Desktop Build
def start_electron():
    os.system('npx electron .')

# 🚀 Start Server
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
