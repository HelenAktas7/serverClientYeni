import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_BASE_URL = 'http://127.0.0.1:5000/api';

const cipherOptions = [
    { value: 'caesar', label: 'Caesar Cipher (Zayıf)' },
    { value: 'vigenere', label: 'Vigenere Cipher (Orta)' },
    { value: 'aes', label: 'AES-128 (Güçlü, Kütüphanesiz Uygulama)' },
];

function MultiCipherForm() {

    const [message, setMessage] = useState('');
    const [key, setKey] = useState('');
    const [result, setResult] = useState('');
    const [mode, setMode] = useState('encrypt');
    const [method, setMethod] = useState('caesar');
    const [error, setError] = useState('');

    useEffect(() => {
        if (method === 'caesar') setKey('3');
        else if (method === 'vigenere') setKey('ANAHTAR');
    }, [method]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setResult('');

        if (!message || !key) {
            setError('Lütfen mesajı ve anahtarı girin.');
            return;
        }

        const endpoint = mode === 'encrypt' ? 'encrypt' : 'decrypt';
        const url = `${API_BASE_URL}/${endpoint}`;

        try {
            const response = await axios.post(url, { message, key, method });
            setResult(response.data.result_message);
        } catch (err) {
            const errMsg = err.response?.data?.error || 'Sunucuya bağlanırken bir hata oluştu.';
            setError(errMsg);
        }
    };

    return (
        <div className="cipher-container">
            <h2>İstemci - Mesaj {mode === 'encrypt' ? 'Şifreleme' : 'Deşifreleme'}</h2>

            <label>Şifreleme Yöntemi Seçin</label>
            <select value={method} onChange={(e) => setMethod(e.target.value)}>
                {cipherOptions.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
            </select>

            <label>İşlem Modu</label>
            <select value={mode} onChange={(e) => setMode(e.target.value)}>
                <option value="encrypt">Şifrele (İstemci Gönderimi)</option>
                <option value="decrypt">Deşifrele (Sunucu Alımı)</option>
            </select>

            <form onSubmit={handleSubmit}>
                <label>Anahtar ({method === 'caesar' ? 'Sayı' : 'Kelime'})</label>
                <input
                    type={method === 'caesar' ? 'number' : 'text'}
                    value={key}
                    onChange={(e) => setKey(e.target.value)}
                    required
                />

                <label>{mode === 'encrypt' ? 'Şifrelenecek Mesaj' : 'Şifreli Mesaj'}</label>
                <textarea
                    rows="5"
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    required
                    placeholder={mode === 'encrypt' ? 'Metni buraya yazın...' : 'Şifreli metni buraya yapıştırın...'}
                ></textarea>

                <button type="submit">{method.toUpperCase()} ile {mode === 'encrypt' ? 'Şifrele' : 'Deşifrele'}</button>
            </form>

            {error && <div className="error-message">{error}</div>}

            {result && (
                <div className="result-box">
                    <label>Sonuç ({mode === 'encrypt' ? 'Şifreli' : 'Deşifreli'} Mesaj):</label>
                    <p>{result}</p>
                </div>
            )}
        </div>
    );
}

export default MultiCipherForm;
