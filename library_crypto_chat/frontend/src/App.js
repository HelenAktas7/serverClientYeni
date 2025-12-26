import React, { useEffect, useState } from "react";
import axios from "axios";
import forge from "node-forge";
import "./App.css";


const API_BASE = "http://127.0.0.1:5051/api";

function b64(bytes) {
  return forge.util.encode64(bytes);
}

function App() {
  const [publicKey, setPublicKey] = useState("");
  const [message, setMessage] = useState("");
  const [algorithm, setAlgorithm] = useState("AES");
  const [result, setResult] = useState("");

  useEffect(() => {
    axios.get(`${API_BASE}/public-key`).then(res => {
      setPublicKey(res.data.public_key);
    });
  }, []);

  const sendMessage = async () => {
    setResult("");

    const rsa = forge.pki.publicKeyFromPem(publicKey);

    const keyLength = algorithm === "AES" ? 16 : 8;
    const secretKey = forge.random.getBytesSync(keyLength);
    const iv = forge.random.getBytesSync(keyLength);

    let cipher;
    if (algorithm === "AES") {
      cipher = forge.cipher.createCipher("AES-CBC", secretKey);
    } else {
      cipher = forge.cipher.createCipher("DES-CBC", secretKey);
    }

    cipher.start({ iv });
    cipher.update(forge.util.createBuffer(message));
    cipher.finish();

    const encryptedKey = rsa.encrypt(secretKey, "RSA-OAEP");

    const payload = {
      algorithm,
      encrypted_key: b64(encryptedKey),
      iv: b64(iv),
      ciphertext: b64(cipher.output.getBytes())
    };

    const response = await axios.post(`${API_BASE}/decrypt`, payload);
    setResult(response.data.plaintext);
  };

  return (
    <div className="container">
      <div className="card">
        <h2>Kütüphaneli Şifreli Haberleşme</h2>

        <label>Şifreleme Algoritması</label>
        <select value={algorithm} onChange={e => setAlgorithm(e.target.value)}>
          <option value="AES">AES-128</option>
          <option value="DES">DES</option>
        </select>

        <label>Gönderilecek Mesaj</label>
        <textarea
          rows="4"
          value={message}
          onChange={e => setMessage(e.target.value)}
          placeholder="Mesajınızı yazın..."
        />

        <button onClick={sendMessage}>Gönder</button>

        {result && (
          <div className="result">
            <strong>Sunucudan Çözülen Mesaj:</strong>
            <span>{result}</span>
          </div>
        )}
      </div>
    </div>
  );

}

export default App;
