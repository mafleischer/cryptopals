#!/usr/bin/env python3

import binascii

hexstr = "1c0111001f010100061a024b53535009181c"
key = "686974207468652062756c6c277320657965"

def xor(bytestr, key):
	if len(bytestr) != len(key):
		print("xor: strings not of equal length")
		exit(1)
	result = b''
	for i in range(0,len(bytestr)):
		result += bytes([bytestr[i] ^ key[i]])
	return(result)

bs = binascii.unhexlify(hexstr)
bk = binascii.unhexlify(key)
print("{}".format(binascii.hexlify(xor(bs, bk))))