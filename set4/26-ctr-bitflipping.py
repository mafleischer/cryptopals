#!/usr/bin/python3

from crypto_algos.aes import aesCTR

if __name__ == '__main__':
    key = b'x' * 16
    nonce = b'12345678'
    plain = b'1234567812345678' * 2
    cipher = aesCTR(plain, key, 128, nonce)
    cipher = bytearray(cipher)
    cipher[0] = cipher[0] & 1
    print(aesCTR(cipher, key, 128, nonce))
