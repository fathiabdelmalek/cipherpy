import math


class HillCipher:
    def __init__(self, key: iter):
        if len(key) == 4:
            self._key = key
        else:
            raise ValueError('key length must be 4')

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key):
        if len(key) == 4:
            self._key = key
        else:
            raise ValueError('key length must be 4')

    def _encrypt_pair(self, pair):
        rp1 = pair[0]
        rp2 = pair[1]
        p1 = chr(ord(pair[0]) - ord('a') + 1)
        p2 = chr(ord(pair[1]) - ord('a') + 1)
        op1 = ord(p1)
        op2 = ord(p2)
        k1 = self._key[0]
        k2 = self._key[1]
        k3 = self._key[2]
        k4 = self._key[3]
        c1 = chr(((ord(p1) * self._key[0] + ord(p2) * self._key[1]) % 26) + ord('a'))
        c2 = chr(((ord(p1) * self._key[2] + ord(p2) * self._key[3]) % 26) + ord('a'))
        print(f"real p1 -> {ord(rp1)} -> {rp1}")
        print(f"real p2 -> {ord(rp2)} -> {rp2}")
        print(f"p1 -> {op1} -> {p1}")
        print(f"p2 -> {op2} -> {p2}")
        print(f"calc 1: [{op1} * {k1} + {op2} * {k2} % {26}] | [{op1} * {k3} + {op2} * {k4} % {26}]")
        print(f"calc 2: [{op1 * k1} + {op2 * k2} % {26}] | [{op1 * k3} + {op2 * k4} % {26}]")
        print(f"calc 3: [{op1 * k1 + op2 * k2} % {26}] | [{op1 * k3 + op2 * k4} % {26}]")
        print(f"calc 4: [{(op1 * k1 + op2 * k2) % 26}] | [{(op1 * k3 + op2 * k4) % 26}]")
        print(f"result: [{(op1 * k1 + op2 * k2) % 26 + ord('a')}] | [{(op1 * k3 + op2 * k4) % 26 + ord('a')}]")
        print(f"char 1: {(op1 * k1 + op2 * k2) % 26 + ord('a')} -> {chr((op1 * k1 + op2 * k2) % 26 + ord('a'))}")
        print(f"char 2: {(op1 * k3 + op2 * k4) % 26 + ord('a')} -> {chr((op1 * k3 + op2 * k4) % 26 + ord('a'))}")
        return chr(ord(c1)) + chr(ord(c2))

    def _decrypt_pair(self, pair):
        p1 = chr(ord(pair[0]) - ord('a') + 1)
        p2 = chr(ord(pair[1]) - ord('a') + 1)
        det = self._key[0] * self._key[3] - self._key[1] * self._key[2]
        if math.gcd(det, 26) != 1:
            raise ValueError("The key matrix is not invertible for the given modulus.")
        det_inverse = pow(det, -1, 26)
        print(det_inverse)
        print((det_inverse * (ord(p1) * self._key[3] - ord(p2) * self._key[1])) % 26)
        print((det_inverse * (ord(p1) * self._key[2] - ord(p2) * self._key[3])) % 26)
        c1 = chr(((det_inverse * (ord(p1) * self._key[3] - ord(p2) * self._key[1])) % 26) + ord('a'))
        c2 = chr(((det_inverse * (-ord(p1) * self._key[2] + ord(p2) * self._key[0])) % 26) + ord('a'))
        return chr(ord(c1)) + chr(ord(c2))

    def encrypt(self, plaintext: str) -> str:
        plaintext = ''.join(filter(str.isalnum, plaintext.lower()))
        ciphertext = ''
        i = 0
        while i < len(plaintext):
            if not plaintext[i].isalpha():
                ciphertext += plaintext[i]
                i += 1
            else:
                pair = plaintext[i:i+2]
                if len(pair) == 1:
                    pair += 'x'
                    i += 1
                elif not pair[1].isalpha():
                    i += 1
                    plaintext = plaintext[:i] + 'x' + plaintext[i:]
                    pair = plaintext[i:i + 2]
                    i -= 1
                ciphertext += self._encrypt_pair(pair)
                i += 2
        return ciphertext

    def decrypt(self, ciphertext: str) -> str:
        ciphertext = ciphertext.lower()
        plaintext = ''
        i = 0
        while i < len(ciphertext):
            if not ciphertext[i].isalpha():
                plaintext += ciphertext[i]
                i += 1
            else:
                pair = ciphertext[i:i + 2]
                plaintext += self._decrypt_pair(pair)
                i += 2
        return plaintext


# Example usage:
if __name__ == "__main__":
    key = (9, 4, 5, 7)
    # key = (9, 5, 2, 4)
    cipher = HillCipher(key)

    message = "HELLO world 2023"
    print("Original message:", message)

    encrypted_message = cipher.encrypt(message)
    print("Encrypted message:", encrypted_message)

    decrypted_message = cipher.decrypt(encrypted_message)
    print("Decrypted message:", decrypted_message)
