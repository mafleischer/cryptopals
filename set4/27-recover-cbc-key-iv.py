#!/usr/bin/python3

from crypto_algos import aes
from crypto_algos.helpers import andBytestrings
from crypto_algos.challenge_specific import setupCBCSecretMaker
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

# change second S to semicolon and E to equal sign through byte flip
#permission_string = b'x' * padding_len + b'01234S78901E3456XXXXX;adminEtrue'
permission_string = b'01234S78901E3456XXXXXSadminEtrue'

cipher = secret_fn(permission_string)
# print(cipher)

# flipped_cipher_iter = cbc.cipherWFlippedBytesGenerator(cipher, 1, 3)
# for c in flipped_cipher_iter:
#	print(c)

# cipher = aes.aesEncrypt(b'xxxxvvvvbbbbggggAAAAAAAAAAAAAAAA', bstr_key, 128, mode='cbc', bstr_IV=b'1234567887654321')

print(hex(cipher[padding_len + 32 + 5]))
print(hex(cipher[padding_len + 32 + 11]))

# for b in range(256):
# 	tmp = bytearray(cipher)
# 	#tmp[padding_len + 32 + 5] = b
# 	tmp[32 + 11] = b
# 	cipher = bytes(tmp)
# 	if _checkAdminPerm(cipher, bstr_key, bstr_IV):
# 		print('yes. byte: {0}'.format(b))
# 		break

b1 = 0xd8
b2 = 0xa8
tmp = bytearray(cipher)
tmp[32 + 5] = b1
tmp[32 + 11] = b2
cipher = bytes(tmp)


if _checkAdminPerm(cipher, bstr_key, bstr_IV):
	print('yes')
else:
	print('no')


clear = aes.aesDecrypt(cipher, bstr_key, 128, mode='cbc',
                       bstr_IV=bstr_IV)

print(clear)
