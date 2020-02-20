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

    hash1 = mac.sha1MAC(key, clear)
    hash2 = mac.sha1MAC(key, clear + b'blablaforged')
    print(hash1)
    print(hash2)