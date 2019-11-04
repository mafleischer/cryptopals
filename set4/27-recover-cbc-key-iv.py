#!/usr/bin/python3

import re
from crypto_algos import aes
from crypto_algos.helpers import xorBytestrings
from crypto_algos.challenge_specific import setupCBCSecretMakerCheckASCII, decryptCBCCheckASCII
from crypto_algos.attack.blockcipher import cbc


def decryption(key, IV):
    def decrypt(cipher):
        return decryptCBCCheckASCII(cipher, key, IV)

    return decrypt

if __name__ == '__main__':

    bstr_key = b'1234567812345678'
    bstr_IV = bstr_key
    secret_fn = setupCBCSecretMakerCheckASCII(bstr_key, bstr_IV)
    decryption_fn = decryption(bstr_key, bstr_IV)
    cipher = bytearray(secret_fn(b'x' * 48))
    print(decryption_fn(cipher))

    # first is decrypted normally -> IV is subtracted
    first_block = cipher[:16]
    # null block causes the last block (which is same as the first block)
    # not to be decrypted fully. Nothing is added after ECB
    # decryption so it leaves the "intermediate state" with the IV still in it
    null_block = b'\x00' * 16
    # flip bits here to trigger print clear text
    flip_block = bytearray(b'\x00' * 16)
    flip_block[13] ^= 1
    crafted_cipher = first_block + null_block + first_block + flip_block + cipher[16:]

    # -> xoring the last clear block (intermediate state of b. 1) with the clear
    # text of block 1 gives the IV

    msg = decryption_fn(crafted_cipher)
    clear = re.search(r"(b'.*')", msg).groups()[0]

    recovered_iv = cbc.recoverIV(eval(clear), 16)
    print(recovered_iv)
    print(aes.aesDecrypt(cipher, recovered_iv, 128, mode='cbc', bstr_IV=recovered_iv))