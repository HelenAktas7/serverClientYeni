import React, { useState, useEffect } from 'react';
import axios from 'axios';

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
        if (method === 'caesar') {
            setKey('3');
        } else if (method === 'vigenere') {
            setKey('ANAHTAR');
        }
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
            const response = await axios.post(url, {

                message: message,
                key: key,
                method: method
            });


            setResult(response.data.result_message);

        } catch (err) {

            const errMsg = err.response?.data?.error || 'Sunucuya bağlanırken bir hata oluştu.';
            setError(errMsg);
        }
    };

    return (
        <div style={{ maxWidth: '600px', margin: 'auto', padding: '20px', border: '1px solid #ccc', borderRadius: '8px' }}>
            <h2>İstemci - Mesaj {mode === 'encrypt' ? 'Şifreleme' : 'Deşifreleme'}</h2>

            { }
            <label style={{ display: 'block', margin: '10px 0 5px' }}>**Şifreleme Yöntemi Seçin**</label>
            <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                style={{ padding: '10px', marginBottom: '15px', width: '100%' }}
            >
                {cipherOptions.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
            </select>

            { }
            <label style={{ display: 'block', margin: '10px 0 5px' }}>**İşlem Modu**</label>
            <select
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                style={{ padding: '10px', marginBottom: '15px', width: '100%' }}
            >
                <option value="encrypt">Şifrele (İstemci Gönderimi)</option>
                <option value="decrypt">Deşifrele (Sunucu Alımı)</option>
            </select>


            <form onSubmit={handleSubmit}>
                { }
                <label style={{ display: 'block', margin: '10px 0 5px' }}>
                    **Anahtar ({method === 'caesar' ? 'Sayı' : 'Kelime'})**
                </label>
                <input
                    type={method === 'caesar' ? 'number' : 'text'}
                    value={key}
                    onChange={(e) => setKey(e.target.value)}
                    required
                    style={{ display: 'block', width: '98%', padding: '8px', margin: '10px 0' }}
                />

                { }
                <label style={{ display: 'block', margin: '10px 0 5px' }}>
                    **{mode === 'encrypt' ? 'Şifrelenecek Mesaj' : 'Şifreli Mesaj'}**
                </label>
                <textarea
                    rows="5"
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    required
                    placeholder={mode === 'encrypt' ? 'Metni buraya yazın...' : 'Şifreli metni buraya yapıştırın...'}
                    style={{ display: 'block', width: '98%', padding: '8px', margin: '10px 0' }}
                ></textarea>

                { }
                <button type="submit" style={{ padding: '10px 20px', backgroundColor: '#007bff', color: 'white', border: 'none', cursor: 'pointer', borderRadius: '4px' }}>
                    {method.toUpperCase()} ile {mode === 'encrypt' ? 'Şifrele' : 'Deşifrele'}
                </button>
            </form>

            { }
            {error && <p style={{ color: 'red', marginTop: '15px' }}>Hata: {error}</p>}
            {result && (
                <div style={{ marginTop: '20px', border: '1px solid #28a745', padding: '10px', backgroundColor: '#e9ffe9', borderRadius: '4px' }}>
                    <label style={{ fontWeight: 'bold' }}>Sonuç ({mode === 'encrypt' ? 'Şifreli' : 'Deşifreli'} Mesaj):</label>
                    <p style={{ wordBreak: 'break-all', marginTop: '5px' }}>{result}</p>
                </div>
            )}
        </div>
    );
}

export default MultiCipherForm;