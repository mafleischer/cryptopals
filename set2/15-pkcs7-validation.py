#!/usr/bin/python3

from crypto_algos import misc
from crypto_algos.challenge_specific import InvalidPKCS7Error, hasValidPKCS7

padded = misc.padPKCS7(b'12345678', 16)
padded = b'1234567812345678\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
padded = b'\xad\x0b\xa3\xab\x1fF\xa5\x035\xb8\xb5\xfbn\xa2\x1a\x04\x19\x1a\x1b\x1c\x1d\x1e\x1f\x10\x1d\x1e\x1f\x10\x19\x1a\x1b\x01'

try:
	hasValidPKCS7(padded, 16)
except InvalidPKCS7Error:
	print('invalid pkcs7')
else:
	print('valid pkcs7')
