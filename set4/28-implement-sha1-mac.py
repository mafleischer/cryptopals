#!/usr/bin/python3

from crypto_algos import aes
from crypto_algos import mac

def decrypt_fn(key, iv):
    def dec(cipher):
        return aes.aesDecrypt(cipher, key, 128, mode='cbc', bstr_IV=iv)
    return dec

if __name__ == '__main__':
    key = b'x' * 16
    iv = b'y' * 16
    clear = b'1234567812345678' * 2
    cipher = aes.aesEncrypt(clear, key, 128, mode='cbc', bstr_IV=iv)
    cipher = bytearray(mac.sha1MACTagCipher(cipher, clear, key))

    dec_fn = decrypt_fn(key, iv)

    if mac.sha1MACAuthMsg(cipher, key, dec_fn):
        print('Auth successful')
    else:
        print('Auth failed')

    cipher[2] ^= 1

    if mac.sha1MACAuthMsg(cipher, key, dec_fn):
        print('Auth successful')
    else:
        print('Auth failed')