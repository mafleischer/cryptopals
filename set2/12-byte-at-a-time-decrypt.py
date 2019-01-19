#!/usr/bin/python3
from crypto_algos.attack.blockcipher import ecb_chosen_plaintext
from crypto_algos import misc
from crypto_algos import aes
import binascii
import os
from crypto_algos.challenge_specific import setupECBSecretMaker

with open("12.txt", 'r') as f:
    txt = f.read()
    clear = bytes(txt, 'ascii')

key = os.urandom(16)
key = b'1234567812345678'
makeSecret = setupECBSecretMaker(key)

clear = ecb_chosen_plaintext.ecbChosenPlaintext(makeSecret)
print(clear)

#print(aes.aesEncrypt(b'xxxxxxRollin\' in', key, 128, mode='ecb', bstr_IV=None))
#print(aes.aesEncrypt(b'xxxxxxRollin\' ic', key, 128, mode='ecb', bstr_IV=None))


#block_iter = cpt_functs.createPlainBlocks()

#l = len([b for b in block_iter])
#print(l)

# with open("blocks", 'ab') as f:
#     for block in block_iter:
#         print(block)
#         f.write(block)
