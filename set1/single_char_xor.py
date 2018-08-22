#!/usr/bin/env python3

import binascii
from allcrypto import single_char_xor

hexstr = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

bstr = binascii.unhexlify(hexstr)

f = open("out.txt", "w")

#print(single_char_xor(bstr))


for c in range(0, 256):
	plain = ""
	for b in bstr:
		plain += chr(c ^ b)
	if plain.isprintable():
		f.write("key {}    ".format(chr(c)) + plain + "\n")

f.close()