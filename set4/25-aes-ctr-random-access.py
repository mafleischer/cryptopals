#!/usr/bin/python3

from crypto_algos.aes import aesCTR, aesCTREdit

if __name__ == '__main__':
    cipher = aesCTR(b'1234567812345678', b'x'*16, 128, b'12345678')
    print(cipher)
    cipher = bytearray(cipher)
    edit = aesCTREdit(cipher, b'x' * 16, b'12345678', 128, 13, b'XYZ')
    print(cipher)
    clear = aesCTR(cipher, b'x'*16, 128, b'12345678')
    print(clear)