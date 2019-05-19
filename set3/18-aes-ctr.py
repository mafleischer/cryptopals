#!/usr/bin/python3

import os
import base64

from crypto_algos import aes

key = os.urandom(16)
nonce = os.urandom(8)
nonce = bytes(8)

msg = b'hello test lalalallalalalalalalallaaa'


cipher = aes.aesCTR(msg, key, 128, nonce)
clear = aes.aesCTR(cipher, key, 128, nonce)

print(clear)

cipher = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
key = b'YELLOW SUBMARINE'
nonce = bytes(8)
clear = aes.aesCTR(cipher, key, 128, nonce)

print(clear)
