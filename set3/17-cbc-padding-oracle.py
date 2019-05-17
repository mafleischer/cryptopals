#!/usr/bin/python3

from crypto_algos import aes
from crypto_algos.challenge_specific import hasValidPKCS7, makeCBCPaddingOracle
from crypto_algos.attack.blockcipher import cbc
from crypto_algos.misc import padPKCS7
import random, base64, os

key = os.urandom(16)
IV = os.urandom(16)

f = open('17-strings.txt', 'r')
b64strings = f.read().split('\n')
choose_str_index = random.randint(0,len(b64strings)-1)
secret = base64.b64decode(b64strings[choose_str_index])
secret_padded = padPKCS7(secret, 16)

for s in b64strings:
	print(base64.b64decode(s))

cipher = aes.aesEncrypt(secret_padded,
                        key, 128, mode='cbc', bstr_IV=IV)
# ^ is this: b'\x8c\x02g\xea\xa2\xd5\xf5\x0e/\xf6B\x0b\xc6/hr\xc7|yTZR\xed)\xa4UU6\x19\x9a\xaa\xa8'

#aes.aesDecrypt(cipher, key, 128, mode='cbc', bstr_IV=IV)



cbcPaddingOracle = makeCBCPaddingOracle(key, IV)
clear = cbc.paddingOracleAttack(cipher, 16, cbcPaddingOracle, IV=IV)
print(clear)
