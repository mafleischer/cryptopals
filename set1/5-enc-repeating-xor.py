#!/usr/bin/env python3

import binascii

plain = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = "ICE"

bstr = bytes(plain, "ascii")
kbstr = bytes(key, "ascii")
cypher = b""
for b in range(0, len(bstr), 3):
    for kb in range(0, len(kbstr)):
        if b + kb < len(bstr):
            cypher += bytes([bstr[b + kb] ^ kbstr[kb]])

print(binascii.hexlify(cypher))