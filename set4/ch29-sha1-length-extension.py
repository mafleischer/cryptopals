#!/usr/bin/python3

import struct
from crypto_algos.submodules.sha1.sha1 import sha1
from crypto_algos.attack.hash import sha1 as attacksha1

if __name__ == "__main__":
    #print(SHA1Padding(b'a'))
    h = bytes(sha1(b'a'), 'ascii')
    print(h)
    print(attacksha1.SHA1RegistersFromHash(h))