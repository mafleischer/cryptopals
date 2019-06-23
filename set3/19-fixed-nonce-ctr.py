#!/usr/bin/python3

import binascii

import os
import base64

from crypto_algos import aes
from crypto_algos.helpers import xorBytestrings, xorStr1AlongStr2, stateGenerator
from crypto_algos.attack.manytimepad import manyTimePadAttackGuessWords, _buildCipherClearDict

f = open('19.txt')
b64_lines = f.read().split('\n')
f.close()
lines = []
for b64l in b64_lines:
    lines.append(base64.b64decode(b64l))

# for DEBUGGING:
#lines = lines[:2]
print(lines)

key = os.urandom(16)
key = b'YELLOW SUBMARINE'
nonce = bytes(8)

crypted_lines = []
hexfile = open('19hex.txt', 'w')
for line in lines:
    crypted_lines.append(aes.aesCTR(line, key, 128, nonce))
    hexstr = binascii.hexlify(aes.aesCTR(line, key, 128, nonce))
    hexfile.write('{}\n'.format(hexstr.decode()))

hexfile.close()

"""
#language_fragments = [b' the ', b'The ', b'There ', b' there ', b' of ', b' my ', b'My ', b' do '] #, b' that ', b'That ', b' that\'s ', b'That\'s ']
language_fragments = [b' have ', b' them ', b' with ', b' of ', b' faces']
include_chars = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"\'!$%&- '

d = _buildCipherClearDict(crypted_lines)
"""

# key_recovered = manyTimePadAttackGuessWords(crypted_lines, language_fragments, include_chars)
# print(key_recovered)

# for crypted_line in crypted_lines:
# 	clear = xorBytestrings(key_recovered, crypted_line, allow_diff_len=True)
# 	print(crypted_line)
# 	print(clear)

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