#!/usr/bin/python3

from Crypto.Cipher import AES
import binascii

def blkFreq(bstr, blkLen):
    # count the occurence of repeated byte blocks of length len
    # return dict of the blocks and the respective frequencies
    blkFreqs = {}
    for i in range(0, len(bstr), blkLen):
        if i+blkLen < len(bstr):
            blk = bstr[i:i+blkLen]
            if blk in blkFreqs:
                blkFreqs[blk] += 1
            else:
                blkFreqs[blk] = 1
        else:
            break
    return(blkFreqs)

f = open("7.txt", "r")

lines = f.readlines()
f.close()

b64 = ""
for l in lines:
    b64 += l

cypher = binascii.a2b_base64(b64)

key = b'YELLOW SUBMARINE'
aes = AES.new(key, AES.MODE_ECB)

clear = aes.decrypt(cypher)

# print(clear.decode('ascii'))


###### 8 #############


f = open("8.txt", "r")

hexlines = f.readlines()
f.close()

lines = [binascii.a2b_hex(l.rstrip()) for l in hexlines]

candidates = []
for l in lines:
    for blklen in range(5,100):
        for blk, freq in blkFreq(l,blklen).items():
            if freq > 1:
                print("blklen {} -  {}  :  {}\n for line {}".format(blklen, blk, freq, l))
                candidates += [binascii.b2a_hex(l)]

print(candidates)

# solution line 133