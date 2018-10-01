import numpy as np
from crypto_algos import aes

np.set_printoptions(formatter={'int':hex})
#cipher = aesEncrypt(bytes("ABCDEFGHIJKLMNOP", "ascii"), b'YELLOW SUBMARINE', 128)

#aesMixColumns(b'\x2b\x28\xab\x09\x7e\xae\xf7\xcf\x15\xd2\x15\x4f\x16\xa6\x88\x3c')
# 328831e0435a3137f6309807a88da234
# 2b28ab097eaef7cf15d2154f16a6883c
#cipher = aesEncrypt(b'\x32\x88\x31\xe0\x43\x5a\x31\x37\xf6\x30\x98\x07\xa8\x8d\xa2\x34', b'\x2b\x28\xab\x09\x7e\xae\xf7\xcf\x15\xd2\x15\x4f\x16\xa6\x88\x3c', 128)

#k = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
#d = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
#cipher = aesEncrypt(d, k, 128)

k = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
d = bytes.fromhex('00112233445566778899aabbccddeeff')
IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff'
cipher = aes.aesEncrypt(d, k, 128)
print(cipher)
cipher = aes.aesEncrypt(d, k, 128, mode='cbc', bstr_IV=IV)
print(cipher)

k = b'YELLOW SUBMARINE'
f = open("7.txt", "rb")
cipher = f.read()
f.close()

clear = aes.aesDecrypt(cipher, k, 128)
print(clear)