#!/usr/bin/python3

import os
import base64

from crypto_algos import aes
from crypto_algos.helpers import xorBytestrings, xorStr1AlongStr2
from crypto_algos.attack.manytimepad import manyTimePadAttackGuessWords

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

language_fragments = [b' the ', b'The ', b'There ', b' there ', b' of ', b' my ', b'My ', b' do '] #, b' that ', b'That ', b' that\'s ', b'That\'s ']
include_chars = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"\'!$%&-'

manyTimePadAttackGuessWords(crypted_lines, language_fragments, include_chars)


# lines_checked = []
# for crypted_line_1 in crypted_lines:
# 	lines_checked.append(crypted_line_1)
# 	crypted_lines.remove(crypted_line_1)

# 	for crypted_line_2 in crypted_lines:
# 		# this removes the many time pad which gives the xor'ed clear messages
# 		xor_of_msgs = xorBytestrings(crypted_line_1, crypted_line_2, allow_diff_len=True)
# 		for fragment in language_fragments:
# 			xorStr1AlongStr2(fragment, xor_of_msgs)
# 		