#!/usr/bin/python3

from crypto_algos import misc
from crypto_algos.challenge_specific import InvalidPKCS7Error, hasValidPKCS7

padded = misc.padPKCS7(b'12345678', 16)
padded = b'1234567812345678\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'

try:
	hasValidPKCS7(padded, 16)
except InvalidPKCS7Error:
	print('invalid pkcs7')
else:
	print('valid pkcs7')
