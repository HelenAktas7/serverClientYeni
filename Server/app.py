from flask import Flask, request, jsonify 
from flask_cors import CORS 
from cipher_methods import CaesarCipher, VigenereCipher ,AESCipher 


app = Flask(__name__)

CORS(app) 

CIPHER_METHODS = {
    "caesar": CaesarCipher(),
    "vigenere": VigenereCipher(),
     "aes": AESCipher(), 
}


def validate_request_data(data):
    """Gelen JSON verisini ve şifreleme yöntemini kontrol eder."""
    
  

    method = data['method'].lower()
    
   
    if method == 'caesar':
        try:
            key = int(data['key'])
        except ValueError:
            return {"error": "Hata: Caesar için 'key' bir tam sayı olmalıdır."}, 400
    elif method == 'aes': 
        key = data['key'] 
        if len(key) != 16:
             return {"error": "Hata: AES için anahtar tam olarak 16 karakter (128 bit) olmalıdır."}, 400
    else:
       
        key = data['key'] 

    return data['message'], key, method



@app.route('/api/encrypt', methods=['POST'])
def encrypt_data():
    """Genel şifreleme uç noktası. Dosya verisi Base64 stringi olarak gelir."""
    data = request.json
    
    validation_result = validate_request_data(data)
    if not isinstance(validation_result, tuple):
        return jsonify(validation_result[0]), validation_result[1]
  
    message, key, method = validation_result
  
    cipher_instance = CIPHER_METHODS[method]
    
    try:
        encrypted_message = cipher_instance.encrypt(message, key)
    except ValueError as e:
        return jsonify({"status": "error", "error": str(e)}), 400

    return jsonify({
        "status": "success",
        "method": method,
        "key_used": key,
        "result_message": encrypted_message
    })


@app.route('/api/decrypt', methods=['POST'])
def decrypt_data():
    """Genel deşifreleme uç noktası."""
    data = request.json
    
    validation_result = validate_request_data(data)
    if not isinstance(validation_result, tuple):
        return jsonify(validation_result[0]), validation_result[1]

    encrypted_message, key, method = validation_result
   
    cipher_instance = CIPHER_METHODS[method] 
    
    try:
        decrypted_message = cipher_instance.decrypt(encrypted_message, key)
    except ValueError as e:
        return jsonify({"status": "error", "error": str(e)}), 400

    return jsonify({
        "status": "success",
        "method": method,
        "key_used": key,
        "result_message": decrypted_message
    })


if __name__ == '__main__':
    app.run(port=5000, debug=True)