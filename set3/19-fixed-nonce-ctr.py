#!/usr/bin/python3

import os
import base64

from crypto_algos import aes

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
for crypted_line in crypted_lines:
	lines_checked.append(crypted_line)
	crypted_lines.remove(crypted_line)
	