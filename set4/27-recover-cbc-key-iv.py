#!/usr/bin/python3

from crypto_algos import aes
from crypto_algos.helpers import andBytestrings
from crypto_algos.challenge_specific import setupCBCSecretMake
from crypto_algos.attack.blockcipher.misc import findCipherBlockJumpLen
from crypto_algos.attack.blockcipher import cbc
import re


def _checkAdminPerm(bstr_cipher, bstr_key, bstr_IV):
    bstr_clear = aes.aesDecrypt(
       	bstr_cipher, bstr_key, 128, mode='cbc', bstr_IV=bstr_IV)
    print(bstr_clear[48:])
    # clear = bstr_clear.decode()
    clear = repr(bstr_clear)
    result = re.search(';admin=true;', clear)
    if result:
    	return True
    else:
    	return False

bstr_key = b'1234567812345678'
bstr_IV = bstr_key
secret_fn = setupCBCSecretMaker(bstr_key, bstr_IV)

# find padding length

padding_len = findCipherBlockJumpLen(secret_fn)

cipher = secret_fn(b'x' * 48)
