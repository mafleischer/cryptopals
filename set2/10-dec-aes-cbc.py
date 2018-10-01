from crypto_algos import aes

k = b'YELLOW SUBMARINE'
f = open("10.txt", "rb")
cipher = f.read()
f.close()
IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
clear = aes.aesDecrypt(cipher, k, 128, mode='cbc', bstr_IV=IV)
print(clear)