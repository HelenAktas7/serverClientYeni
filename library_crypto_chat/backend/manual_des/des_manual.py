def xor_strings(a, b):
    result = ""
    for i in range(len(a)):
        result += chr(ord(a[i]) ^ ord(b[i % len(b)]))
    return result

def feistel_function(right, key):
    return xor_strings(right, key)


def split_text(text):
    mid = len(text) // 2
    return text[:mid], text[mid:]


def pad_text(text):
    if len(text) % 2 != 0:
        text += " "
    return text


def generate_subkeys(key, rounds=4):
    subkeys = []
    for i in range(rounds):
        subkeys.append(key[i % len(key)] * (len(key)))
    return subkeys


def encrypt(plaintext, key):
    plaintext = pad_text(plaintext)
    L, R = split_text(plaintext)
    subkeys = generate_subkeys(key)

    for i in range(4):
        temp = R
        f_output = feistel_function(R, subkeys[i])
        R = xor_strings(L, f_output)
        L = temp

    return L + R


def decrypt(ciphertext, key):
    L, R = split_text(ciphertext)
    subkeys = generate_subkeys(key)

    for i in reversed(range(4)):
        temp = L
        f_output = feistel_function(L, subkeys[i])
        L = xor_strings(R, f_output)
        R = temp

    return L + R

def encrypt_api(message, key):
    return encrypt(message, key)


if __name__ == "__main__":
    print("=== MANUEL DES (SADELESTIRILMIS) ===")

    plaintext = input("Plaintext girin: ")
    key = input("Anahtar girin: ")

    encrypted = encrypt(plaintext, key)
    print("Sifreli Metin:", encrypted)

    decrypted = decrypt(encrypted, key)
    print("Cozulmus Metin:", decrypted)
