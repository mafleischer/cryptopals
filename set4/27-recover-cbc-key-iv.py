#!/usr/bin/python3

from crypto_algos import aes
from crypto_algos.helpers import andBytestrings
from crypto_algos.challenge_specific import setupCBCSecretMakerCheckASCII
from crypto_algos.attack.blockcipher.misc import findCipherBlockJumpLen
from crypto_algos.attack.blockcipher import cbc
import re

bstr_key = b'1234567812345678'
bstr_IV = bstr_key
secret_fn = setupCBCSecretMakerCheckASCII(bstr_key, bstr_IV)

cipher = secret_fn(b'x' * 48)
