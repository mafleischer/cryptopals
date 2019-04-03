#!/usr/bin/python3

from crypto_algos import aes
from crypto_algos.helpers import andBytestrings
from crypto_algos.challenge_specific import setupCBCSecretMaker
from crypto_algos.attack.blockcipher.misc import findCipherBlockJumpLen
import re


def _checkAdminPerm(bstr_cipher, bstr_key, bstr_IV):
    bstr_clear = aes.aesDecrypt(
        bstr_cipher, bstr_key, 128, mode='cbc', bstr_IV=bstr_IV)
    clear = bstr_clear.decode()
    result = re.search(';admin=true;', clear)
    if result:
    	return True
    else:
    	return False


bstr_key = b'1234567812345678'
bstr_IV = b'1234567887654321'
secret_fn = setupCBCSecretMaker(bstr_key, bstr_IV)

# find padding length

padding_len = findCipherBlockJumpLen(secret_fn)

# change second S to semicolon and E to equal sign through byte flip
permission_string = b'x' * padding_len + b'12345S781E345678XXXXXSadminEtrue'

cipher = secret_fn(b'aaaa;admin=true')
cipher = secret_fn(permission_string)
print(cipher)

#cipher = aes.aesEncrypt(b'xxxxvvvvbbbbggggAAAAAAAAAAAAAAAA', bstr_key, 128, mode='cbc', bstr_IV=b'1234567887654321')
# print(cipher)

#cipher = andBytestrings(cipher, b'')
# cipher = b'#\xca\xc4\xc3\xea\xaf\x88@\xde\x17G\xa5\x8d\x17\x9a\xb5\xaa\xd2\xea\xe8GJ\x93\x152I\xa0|1\xceo0'
# cipher =
# b'#\xca\xc8\xc3\xea\xaf\x88@\xde\x17G\xa5\x8d\x17\x9a\xb5\xaa\xd2\xea\xe8GJ\x93\x152I\xa0|1\xceo0'

if _checkAdminPerm(cipher, bstr_key, bstr_IV):
	print('yes')
else:
	print('no')


clear = aes.aesDecrypt(cipher, bstr_key, 128, mode='cbc',
                       bstr_IV=bstr_IV)

print(clear)
