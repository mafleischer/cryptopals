#!/usr/bin/python3

from crypto_algos.helpers import xorBytestrings
from crypto_algos.aes import aesCTR, aesCTREdit
from crypto_algos.attack.streamcipher.ctr import aesCTREditRecoverPlain

if __name__ == '__main__':
    key = b'x' * 16
    nonce = b'12345678'

    # editing
    cipher = aesCTR(b'12345678123456781234567812345678', key, 128, nonce)
    cipher = bytearray(cipher)
    edit = aesCTREdit(cipher, key, nonce, 128, 0, b'X' * 3)
    clear = aesCTR(cipher, b'x'*16, 128, nonce)
    print(clear)

    # recover plain text
    cipher = aesCTR(b'12345678123456781234567812345678', key, 128, nonce)
    cipher = bytearray(cipher)
    plain = aesCTREditRecoverPlain(aesCTREdit, cipher, key, nonce, 128, 0, b'X')
    print(plain)