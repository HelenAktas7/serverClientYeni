import base64
from abc import ABC, abstractmethod 

class CipherBase(ABC):
    """Tüm şifreleme sınıfları için temel arayüz (interface)."""
    
    @abstractmethod
    def encrypt(self, data: str, key) -> str: 
        pass

    @abstractmethod
    def decrypt(self, data: str, key) -> str:
        pass



class CaesarCipher(CipherBase):
    """Kütüphane kullanmadan Sezar Şifresi (Caesar Cipher) uygulaması."""

    def __init__(self):
        self.upper_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        self.lower_alphabet = 'abcdefghijklmnopqrstuvwxyz'
        self.digits = '0123456789'
        
        self.alpha_len = len(self.upper_alphabet)
        self.digit_len = len(self.digits)

    def _transform_char(self, char: str, key: int, mode: str) -> str:
        """Tek bir karakteri kaydırarak şifreler/deşifreler."""
        multiplier = 1 if mode == 'encrypt' else -1

        if char in self.upper_alphabet:
            alphabet = self.upper_alphabet
            length = self.alpha_len
        elif char in self.lower_alphabet:
            alphabet = self.lower_alphabet
            length = self.alpha_len
        elif char in self.digits:
            alphabet = self.digits
            length = self.digit_len
        else:
            return char
        
        norm_key = (key * multiplier) % length
        current_index = alphabet.index(char)
        new_index = (current_index + norm_key) % length
        
        return alphabet[new_index]

    def process_text(self, text: str, key: int, mode: str) -> str:
        return "".join(self._transform_char(char, key, mode) for char in text)

    def encrypt(self, plaintext: str, key) -> str:
        return self.process_text(plaintext, key, mode='encrypt')

    def decrypt(self, ciphertext: str, key) -> str:
        return self.process_text(ciphertext, key, mode='decrypt')



class VigenereCipher(CipherBase):
    """Kütüphane kullanmadan Vigenère Şifresi (Vigenère Cipher) uygulaması."""
    
    def __init__(self):
        self.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        self.alpha_len = len(self.alphabet)

    def _prepare_key(self, key: str, text_len: int) -> str:
        """Anahtarı normalize eder (büyük harfe çevirir ve metin uzunluğuna uzatır)."""
        key = "".join(filter(str.isalpha, key)).upper()
        if not key:
             raise ValueError("Vigenère için anahtar (key) alfabetik karakterler içermelidir.")
             
        full_key = (key * (text_len // len(key))) + key[:text_len % len(key)]
        return full_key

    def _vigenere_transform(self, char: str, key_char: str, mode: str) -> str:
        """Tek bir karakteri Vigenère kaydırma tablosuna göre şifreler/deşifreler."""
        char_upper = char.upper()
        
        if char_upper not in self.alphabet:
            return char
        
        char_index = self.alphabet.index(char_upper)
        key_index = self.alphabet.index(key_char)
        
        if mode == 'encrypt':
            new_index = (char_index + key_index) % self.alpha_len
        else: 
            new_index = (char_index - key_index) % self.alpha_len
        
        new_char = self.alphabet[new_index]
        return new_char if char == char_upper else new_char.lower()


    def encrypt(self, plaintext: str, key: str) -> str:
        alphabetic_chars = "".join(filter(str.isalpha, plaintext))
        try:
            full_key = self._prepare_key(key, len(alphabetic_chars))
        except ValueError as e:
            raise e
        
        ciphertext = []
        key_idx = 0
        
        for char in plaintext:
            if char.isalpha():
                cipher_char = self._vigenere_transform(char, full_key[key_idx], mode='encrypt')
                ciphertext.append(cipher_char)
                key_idx += 1
            else:
                ciphertext.append(char)
                
        return "".join(ciphertext)

    def decrypt(self, ciphertext: str, key: str) -> str:
        alphabetic_chars = "".join(filter(str.isalpha, ciphertext))
        
        try:
            full_key = self._prepare_key(key, len(alphabetic_chars))
        except ValueError as e:
            raise e

        plaintext = []
        key_idx = 0
        
        for char in ciphertext:
            if char.isalpha():
                plain_char = self._vigenere_transform(char, full_key[key_idx], mode='decrypt')
                plaintext.append(plain_char)
                key_idx += 1
            else:
                plaintext.append(char)
                
        return "".join(plaintext)

S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xee, 0xfb, 0x4f, 0xcd, 0x03, 0xa9, 0xef, 0x37, 0xe7, 0x5e, 0x61, 0x9d, 0x42, 0x79, 0xea,
    0xcb, 0x8c, 0x19, 0xf5, 0x85, 0x8b, 0x6a, 0x4a, 0x8d, 0x8e, 0x6a, 0x6b, 0x3a, 0x08, 0x6e, 0x7a,
    0x79, 0x28, 0x44, 0x5d, 0x7c, 0x3c, 0x47, 0x8d, 0x08, 0x22, 0x29, 0x34, 0x49, 0x0d, 0x4f, 0xa9,
    0x88, 0x10, 0x51, 0x5c, 0x1b, 0x60, 0x1a, 0xe2, 0x24, 0x6d, 0x99, 0x94, 0x57, 0x56, 0xf6, 0x54,
    0xcf, 0x2d, 0x4d, 0x0a, 0x14, 0x64, 0xf8, 0x0b, 0xdd, 0x2a, 0x91, 0x16, 0x8f, 0x87, 0xcc, 0xf5,
    0x78, 0x30, 0x51, 0xf3, 0x46, 0x4a, 0x5a, 0x7f, 0xbf, 0x83, 0x10, 0x07, 0x25, 0x32, 0x0b, 0x9d,
    0x93, 0xc9, 0x9f, 0xaf, 0xe5, 0xa2, 0x61, 0xfc, 0xc7, 0x31, 0x84, 0x17, 0xf7, 0xd4, 0x2e, 0x0d,
    0x40, 0x58, 0xca, 0x69, 0x7b, 0xf2, 0x46, 0xe5, 0xd0, 0x50, 0xd8, 0x12, 0xc4, 0x90, 0x2b, 0x5a,
    0x0a, 0xc7, 0x51, 0x25, 0xfd, 0x02, 0xa9, 0xf6, 0xee, 0x86, 0x40, 0x59, 0x63, 0x1b, 0x4f, 0x78,
    0xfd, 0x5f, 0x45, 0x36, 0x8f, 0xfc, 0x6e, 0x12, 0x77, 0x45, 0xfa, 0x6c, 0x90, 0x52, 0xd1, 0x9f,
    0x78, 0x39, 0x51, 0x67, 0x54, 0x4f, 0xee, 0x0c, 0x4a, 0x2c, 0x42, 0x3c, 0x9f, 0xd3, 0x1d, 0x14,
    0x17, 0x0d, 0x44, 0x6b, 0x79, 0x68, 0x45, 0x2b, 0x6e, 0xa1, 0x84, 0x0d, 0x17, 0x5b, 0x1a, 0xb7,
    0x53, 0x0e, 0x1d, 0x9d, 0x81, 0x16, 0x68, 0x0a, 0xc6, 0x4c, 0xc3, 0x42, 0x3a, 0x63, 0x74, 0x4c,
    0x2c, 0x6d, 0x8d, 0xcc, 0x7a, 0xe4, 0x3e, 0x6e, 0x42, 0x2a, 0x16, 0x66, 0x09, 0x1f, 0x58, 0x32,
    0xf8, 0x6b, 0x1c, 0x03, 0x9d, 0x76, 0x6e, 0x4d, 0x9c, 0x23, 0x0c, 0xe8, 0xd2, 0x60, 0x6e, 0x5f,
    0x61, 0x6a, 0x72, 0x3b, 0x95, 0x32, 0xc3, 0x26, 0x6e, 0x0b, 0x68, 0x86, 0x6f, 0x42, 0x3b, 0x6d,
    0x54, 0x1f, 0x7e, 0x4b, 0x6e, 0x5d, 0x6a, 0x4f, 0x4b, 0x71, 0x7f, 0x99, 0xf6, 0x17, 0x3f, 0xd6,
    0x1a, 0x1f, 0x9e, 0x46, 0x6e, 0x27, 0x3c, 0x6f, 0x9f, 0x6c, 0x1b, 0x3e, 0x7d, 0x47, 0x44, 0x3c,
    0x0a, 0x1e, 0x9a, 0x5c, 0x5b, 0x4d, 0x0f, 0x7e, 0x51, 0x8b, 0x6f, 0x0b, 0x8d, 0x64, 0x2b, 0x16,
    0x66, 0x78, 0x83, 0xe3, 0x20, 0x47, 0x2b, 0x3e, 0x7a, 0x8d, 0x4f, 0x2b, 0x17, 0x8b, 0x4d, 0x6f
]

INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe8, 0xf1, 0x47, 0x1c, 0x9c, 0x71, 0x6a, 0x1d,
    0x10, 0x9a, 0x61, 0x04, 0x14, 0x0c, 0x24, 0x3e, 0x55, 0x5f, 0x26, 0x6f, 0x0b, 0x63, 0x88, 0x82,
    0x2d, 0xe1, 0x7a, 0xaa, 0xba, 0xee, 0xf6, 0x3e, 0x92, 0x6d, 0xd0, 0x58, 0x83, 0x99, 0x8e, 0x5c,
    0x54, 0x59, 0x38, 0x28, 0x74, 0x3c, 0x27, 0x91, 0x10, 0xf3, 0x83, 0x17, 0x7c, 0xa8, 0x2c, 0x42,
    0x44, 0xf9, 0x41, 0xb1, 0x5f, 0x5a, 0x06, 0xb7, 0x9e, 0x4d, 0x6d, 0x7f, 0x57, 0x6a, 0x9d, 0x8c,
    0x7a, 0xb8, 0xc4, 0x88, 0x9f, 0x58, 0x17, 0xd2, 0x7f, 0x9f, 0x49, 0x5f, 0x72, 0xd2, 0x24, 0x54,
    0x1e, 0x81, 0x1f, 0x82, 0x8c, 0x66, 0x2a, 0x2d, 0x29, 0x0f, 0x04, 0x51, 0x29, 0x62, 0x3d, 0x53,
]

R_CON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
MIX_COL_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]
INV_MIX_COL_MATRIX = [
    [0x0e, 0x0b, 0x0d, 0x09],
    [0x09, 0x0e, 0x0b, 0x0d],
    [0x0d, 0x09, 0x0e, 0x0b],
    [0x0b, 0x0d, 0x09, 0x0e]
]

class AESCipher(CipherBase):
    """Kütüphanesiz (From-scratch) AES-128 uygulaması."""
    def __init__(self):
        self.key_size = 16 
        self.nr = 10 
        self.nb = 4 
    def _gf_mult(self, a, b):
        p = 0
        while b:
            if b & 1:
                p ^= a
            a <<= 1
            if a & 0x100: 
                a ^= 0x11B 
            b >>= 1
        return p % 256

    def _key_expansion(self, key_bytes):
        key_words = [key_bytes[i*4:i*4+4] for i in range(self.key_size // 4)]
        expanded_key = list(key_words)
        
        while len(expanded_key) < self.nb * (self.nr + 1):
            temp = list(expanded_key[-1])
            
            if len(expanded_key) % self.nb == 0:
                temp.append(temp.pop(0))
                temp = [S_BOX[b] for b in temp]
                i = len(expanded_key) // self.nb - 1
                temp[0] ^= R_CON[i]
            
            word_idx = len(expanded_key) - self.nb
            new_word = [temp[j] ^ expanded_key[word_idx + j][j] for j in range(4)]
            expanded_key.append(new_word)
            
        flat_key = []
        for word in expanded_key:
            flat_key.extend(word)
        return flat_key

    def _add_round_key(self, state, round_key):
        for i in range(16):
            state[i] ^= round_key[i]
        return state

    def _sub_bytes(self, state, s_box):
        return [s_box[b] for b in state]

    def _shift_rows(self, state):
        new_state = [0] * 16
        
        for c in range(4): new_state[4 * c + 0] = state[4 * c + 0]
        
        new_state[4 * 0 + 1] = state[4 * 1 + 1]
        new_state[4 * 1 + 1] = state[4 * 2 + 1]
        new_state[4 * 2 + 1] = state[4 * 3 + 1]
        new_state[4 * 3 + 1] = state[4 * 0 + 1]

        new_state[4 * 0 + 2] = state[4 * 2 + 2]
        new_state[4 * 1 + 2] = state[4 * 3 + 2]
        new_state[4 * 2 + 2] = state[4 * 0 + 2]
        new_state[4 * 3 + 2] = state[4 * 1 + 2]

        new_state[4 * 0 + 3] = state[4 * 3 + 3]
        new_state[4 * 1 + 3] = state[4 * 0 + 3]
        new_state[4 * 2 + 3] = state[4 * 1 + 3]
        new_state[4 * 3 + 3] = state[4 * 2 + 3]
        
        return new_state

    def _mix_columns(self, state, matrix):
        new_state = [0] * 16
        for c in range(4): 
            for r in range(4): 
                val = 0
                for i in range(4):
                    val ^= self._gf_mult(matrix[r][i], state[4 * c + i]) 
                new_state[4 * c + r] = val
        return new_state

    def _aes_encrypt_block(self, block, expanded_key):
        state = list(block)
        state = self._add_round_key(state, expanded_key[0:16])
        
        for r in range(1, self.nr):
            start = r * 16
            state = self._sub_bytes(state, S_BOX)
            state = self._shift_rows(state)
            state = self._mix_columns(state, MIX_COL_MATRIX)
            state = self._add_round_key(state, expanded_key[start:start + 16])
            
        start = self.nr * 16
        state = self._sub_bytes(state, S_BOX)
        state = self._shift_rows(state)
        state = self._add_round_key(state, expanded_key[start:start + 16])
        
        return bytes(state)

    def _aes_decrypt_block(self, block, expanded_key):
        state = list(block)
        
        state = self._add_round_key(state, expanded_key[self.nr * 16: (self.nr + 1) * 16])
        
        for r in range(self.nr - 1, 0, -1):
            start = r * 16
            state = self._shift_rows(state)
            state = self._sub_bytes(state, INV_S_BOX)
            state = self._add_round_key(state, expanded_key[start:start + 16])
            state = self._mix_columns(state, INV_MIX_COL_MATRIX)

        state = self._shift_rows(state)
        state = self._sub_bytes(state, INV_S_BOX)
        state = self._add_round_key(state, expanded_key[0:16])

        return bytes(state)

    def encrypt(self, message_base64, key):
        if len(key) != 16:
            raise ValueError("AES-128 için anahtar tam olarak 16 karakter (128 bit) uzunluğunda olmalıdır.")

        try:
            header, encoded_data = message_base64.split(',', 1)
            data_bytes = base64.b64decode(encoded_data)
        except:
            raise ValueError("Geçersiz Base64 formatı. Lütfen Base64 ile kodlanmış bir girdi sağlayın.")
        
        key_bytes = key.encode('utf-8')
        expanded_key = self._key_expansion(key_bytes)
        
        padding_len = 16 - (len(data_bytes) % 16)
        padding = bytes([padding_len] * padding_len)
        padded_data = data_bytes + padding
        
        encrypted_blocks = []
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i + 16]
            encrypted_blocks.append(self._aes_encrypt_block(block, expanded_key))
            
        encrypted_bytes = b''.join(encrypted_blocks)
        b64_output = base64.b64encode(encrypted_bytes).decode('utf-8')
        
        return f"{header},{b64_output}"


    def decrypt(self, encrypted_base64, key):
        if len(key) != 16:
            raise ValueError("AES-128 için anahtar tam olarak 16 karakter (128 bit) uzunluğunda olmalıdır.")

        try:
            header, encoded_data = encrypted_base64.split(',', 1)
            encrypted_bytes = base64.b64decode(encoded_data)
        except:
            raise ValueError("Geçersiz Base64 formatı veya geçersiz Base64 içeriği.")
        
        if len(encrypted_bytes) % 16 != 0:
            raise ValueError("Deşifrelenecek veri boyutu 16 baytın katı olmalıdır.")

        key_bytes = key.encode('utf-8')
        expanded_key = self._key_expansion(key_bytes)
        
        decrypted_blocks = []
        for i in range(0, len(encrypted_bytes), 16):
            block = encrypted_bytes[i:i + 16]
            decrypted_blocks.append(self._aes_decrypt_block(block, expanded_key))
            
        decrypted_padded_bytes = b''.join(decrypted_blocks)
        
        try:
            padding_len = decrypted_padded_bytes[-1]
            if not (1 <= padding_len <= 16) or not all(decrypted_padded_bytes[-i] == padding_len for i in range(1, padding_len + 1)):
                raise ValueError
                
            decrypted_bytes = decrypted_padded_bytes[:-padding_len]
        except (IndexError, ValueError):
            raise ValueError("Deşifreleme hatası veya yanlış anahtar. Padding (doldurma) doğrulanamadı.")
            
        b64_output = base64.b64encode(decrypted_bytes).decode('utf-8')
        
        return f"{header},{b64_output}"