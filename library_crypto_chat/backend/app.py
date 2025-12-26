from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

from manual_des.des_manual import encrypt_api as manual_des_encrypt

app = Flask(__name__)

CORS(app, resources={r"/api/*": {"origins": "*"}})

RSA_KEY = RSA.generate(2048)
RSA_PUBLIC_KEY = RSA_KEY.publickey()

def b64e(b):
    return base64.b64encode(b).decode()

def b64d(s):
    return base64.b64decode(s.encode())

@app.get("/api/public-key")
def get_public_key():
    return jsonify({
        "public_key": RSA_PUBLIC_KEY.export_key().decode()
    })

@app.post("/api/decrypt")
def decrypt_message():
    data = request.json
    algorithm = data["algorithm"]

    encrypted_key = b64d(data["encrypted_key"])
    iv = b64d(data["iv"])
    ciphertext = b64d(data["ciphertext"])

    rsa_cipher = PKCS1_OAEP.new(RSA_KEY)
    secret_key = rsa_cipher.decrypt(encrypted_key)

    if algorithm == "AES":
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        plaintext = plaintext[:-plaintext[-1]]

    elif algorithm == "DES":
        cipher = DES.new(secret_key, DES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        plaintext = plaintext[:-plaintext[-1]]

    else:
        return jsonify({"error": "Unknown algorithm"}), 400

    return jsonify({
        "plaintext": plaintext.decode()
    })

@app.post("/api/manual-des/encrypt")
def manual_des_encrypt_route():
    data = request.json
    message = data.get("message")
    key = data.get("key")

    if not message or not key:
        return jsonify({"error": "Mesaj ve anahtar zorunludur"}), 400

    ciphertext = manual_des_encrypt(message, key)

    return jsonify({
        "algorithm": "Manual DES",
        "ciphertext": ciphertext
    })
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5051, debug=True)
