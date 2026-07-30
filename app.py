from flask import Flask, request, jsonify, send_from_directory
import os
import base64
import threading
import webbrowser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__, static_folder='.', static_url_path='')

# Encryption functions (operate on in-memory bytes, not files on disk)
def generate_key():
    return os.urandom(32)

def encrypt_bytes(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext

def decrypt_bytes(data, key):
    if len(data) < 16:
        raise ValueError("Decryption failed: file is too small to contain a valid IV")

    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    except ValueError as e:
        raise ValueError("Decryption failed: invalid key or corrupted file") from e

    try:
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
    except ValueError as e:
        raise ValueError("Decryption failed: invalid key or corrupted file") from e

    return plaintext

# API Endpoints
@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        key = generate_key()
        plaintext = file.read()
        ciphertext = encrypt_bytes(plaintext, key)
        out_name = f"{file.filename}.encrypted"

        # Key and file data travel together in ONE JSON response.
        # No custom headers, no second request - nothing for a proxy,
        # CDN, or browser quirk to strip or drop.
        return jsonify({
            "status": "success",
            "key": key.hex(),
            "filename": out_name,
            "data": base64.b64encode(ciphertext).decode("ascii"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    if 'key' not in request.form:
        return jsonify({"error": "No key provided"}), 400

    file = request.files['file']

    try:
        key = bytes.fromhex(request.form['key'].strip())
        if len(key) != 32:
            return jsonify({"error": "Key must be 256 bits (64 hex characters)"}), 400
    except ValueError:
        return jsonify({"error": "Invalid key format. Use hexadecimal characters only"}), 400

    try:
        ciphertext = file.read()
        plaintext = decrypt_bytes(ciphertext, key)

        original_name = file.filename
        if original_name.endswith('.encrypted'):
            original_name = original_name[: -len('.encrypted')]

        return jsonify({
            "status": "success",
            "filename": original_name,
            "data": base64.b64encode(plaintext).decode("ascii"),
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Serve Frontend
@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

def open_browser():
    webbrowser.open_new('http://localhost:5000')

if __name__ == "__main__":
    threading.Timer(1, open_browser).start()
    app.run(port=5000, debug=True)