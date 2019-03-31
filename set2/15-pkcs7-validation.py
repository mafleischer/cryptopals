#!/usr/bin/python3

from crypto_algos import misc


class InvalidPKCS7Error(Exception):
    pass


def _hasValidPKCS7(bstr, blocksize):
    """ presume bstr is padded; check if it has valid pkcs7 padding """
    last_byte = bstr[-1]
    padding = bstr[-last_byte:]
    if not padding.count(last_byte) == last_byte:
    	raise InvalidPKCS7Error
    if last_byte == blocksize:
    	return None

    stripped_once = bstr[:-last_byte]
    last_byte = stripped_once[-1]
    padding = stripped_once[-last_byte:]
    if not padding.count(last_byte) == last_byte:
    	raise InvalidPKCS7Error
    else:
    	return None

padded = misc.padPKCS7(b'12345678', 16)
padded = b'1234567812345678\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'

try:
	_hasValidPKCS7(padded, 16)
except InvalidPKCS7Error:
	print('invalid pkcs7')
else:
	print('valid pkcs7')
