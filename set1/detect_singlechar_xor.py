#!/usr/bin/python3

import base64
import binascii
from allcrypto import single_char_xor

f1 = open("4.txt", "r")
f2 = open("out.txt", "w")

strings = f1.readlines()
good_strs = []
plain = ""
for hexstr in strings:
	hexstr = hexstr.rstrip()
	s = binascii.unhexlify(hexstr)
	plain += single_char_xor(s) + '\n'
	"""
	count = {}
	for b in s:
		if b in count:
			count[b] += 1
		else:
			count[b] = 1
	max_element_index = max(count, key=lambda i: count[i])

	if count[max_element_index] > 4:
		#f2.write(hexstr + "\n")
		good_strs.append(s)
"""

"""
for s in good_strs:
	for k in range(0, 256):
		plain += "{} : {}:  \n".format(s, k)
		for b in s:
			plain += chr(b ^ k)
		plain += "\n"
"""
f2.write(plain)
f1.close()
f2.close()
#print("{}".format(good_strs))