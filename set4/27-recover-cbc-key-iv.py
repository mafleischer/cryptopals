#!/usr/bin/python3

from crypto_algos import aes
from crypto_algos.helpers import andBytestrings
from crypto_algos.challenge_specific import setupCBCSecretMakerCheckASCII, decryptCBCCheckASCII
import re

def decryption(key, IV):
    def decrypt(cipher):
        decryptCBCCheckASCII(cipher, key, IV)
    return decrypt
bstr_key = b'1234567812345678'
bstr_IV = bstr_key
secret_fn = setupCBCSecretMakerCheckASCII(bstr_key, bstr_IV)
decryption_fn = decryption(bstr_key, bstr_IV)
cipher = secret_fn(b'x' * 48)
print(decryptCBCCheckASCII(cipher, bstr_key, bstr_IV))