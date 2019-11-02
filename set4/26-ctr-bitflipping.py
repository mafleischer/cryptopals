#!/usr/bin/python3

import re
from crypto_algos.aes import aesCTR
from crypto_algos.challenge_specific import setupCTRSecretMaker

def _checkAdminPerm(bstr_cipher, bstr_key, nonce):
    bstr_clear = aesCTR(bstr_cipher, bstr_key, 128, nonce)
    # print(bstr_clear[48:])
    # clear = bstr_clear.decode()
    clear = repr(bstr_clear)
    result = re.search(';admin=true;', clear)
    if result:
    	return True
    else:
    	return False

if __name__ == '__main__':
    key = b'x' * 16
    nonce = b'12345678'
    # plain = b'1234567812345678' * 2
    # cipher = aesCTR(plain, key, 128, nonce)
    # cipher = bytearray(cipher)
    # cipher[0] = cipher[0] & 1
    # print(aesCTR(cipher, key, 128, nonce))

    userdata = b'blaXadminYtrue'
    ctr_secret_fn = setupCTRSecretMaker(key, nonce)
    cipher = ctr_secret_fn(userdata)
    # that's actually not flipping bits but going directly for the correct cipher byte
    keybyte1 = cipher[35] ^ ord(b'X')
    substitute1 = keybyte1 ^ ord(b';')
    keybyte2 = cipher[41] ^ ord(b'Y')
    substitute2 = keybyte2 ^ ord(b'=')
    cipher = bytearray(cipher)
    cipher[35] = substitute1
    cipher[41] = substitute2

    if _checkAdminPerm(cipher,key,nonce):
        print("Admin perm")
    else:
        print("No admin perm")

    # bit flip version:
    userdata = b'bla:admin<true'
    ctr_secret_fn = setupCTRSecretMaker(key, nonce)
    cipher = ctr_secret_fn(userdata)
    cipher = bytearray(cipher)
    # ; and = is 1 after : and <
    cipher[35] = cipher[35] ^ 1
    cipher[41] = cipher[41] ^ 1

    if _checkAdminPerm(cipher, key, nonce):
        print("Admin perm")
    else:
        print("No admin perm")