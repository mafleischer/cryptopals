#!/usr/bin/python3

import os
import base64

from crypto_algos import aes
from crypto_algos.helpers import xorStr1AlongStr2

f = open('19.txt')
b64_lines = f.read().split('\n')
f.close()
lines = []
for b64l in b64_lines:
	lines.append(base64.b64decode(b64l))

key = os.urandom(16)
nonce = bytes(8)
crypted_lines = []
for line in lines:
	crypted_lines.append(aes.aesCTR(line, key, 128, nonce))

word = ' the '

lines_checked = []
for crypted_line_1 in crypted_lines:
	lines_checked.append(crypted_line_1)
	crypted_lines.remove(crypted_line_1)

	for crypted_line_2 in crypted_lines:
		# this removes the many time pad which gives the xor'ed clear messages
		xor_of_msgs = xorBytestrings(crypted_line_1, crypted_line_2, allow_diff_len=True)

xorStr1AlongStr2(b'1234567890123123123123123', b'123')
		