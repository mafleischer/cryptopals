#!/usr/bin/env python3

import binascii
import numpy
import collections
import itertools

key = "ICE"
f1 = open("6.txt", "r")
t = f1.readlines()
f1.close()

cypher = b""
for l in t:
    cypher += binascii.a2b_base64(l)

def hamming(bstr1, bstr2):
    if len(bstr1) != len(bstr2):
        print("xor not equal len!")
        exit(1)
    diff = b''
    b1 = bstr1
    b2 = bstr2
    diff = xor(b1, b2)
    distance = 0
    for b in diff:
        distance += bin(b).count("1")
    return(distance)


def xor(bstr1, bstr2):
    if len(bstr1) != len(bstr2):
        print("xor not equal len!")
        exit(1)
    result = b''
    for i in range(0, len(bstr1)):
        result += bytes([bstr1[i] ^ bstr2[i]])
    return(result)

def xor_repeat(bstr, kbstr, keylen):
    cypher = b''
    for b in range(0, len(bstr), keylen):
        for kb in range(0, len(kbstr)):
            if b + kb < len(bstr):
                cypher += bytes([bstr[b + kb] ^ kbstr[kb]])
    return(cypher)

def break_1_char_xor(bstr, num_freq_chars, brute=False):
    frequent_chars = {' ':3,'e':2,'t':1}

    #frequent_chars = {'e':3,'t':2, 'a': 1}
    freqs = char_freq(bstr, num_freq_chars)
    key = b""
    for x,y in zip(sorted(frequent_chars, key=frequent_chars.__getitem__, reverse=True), freqs):
        key += bytes([ord(x) ^ y[0]])
    if key.count(key[0]) == len(key):
        return(bytes([key[0]]))
    else:
        return(None)

def make_blk_matrice(blockSample):
    blk_len = len(blockSample[0])
    block_matrice = []
    for blk in blockSample:
        for byte in blk:
            if len(block_matrice) == 0:
                # first row
                block_matrice = [[byte]]
            else:
                if len(block_matrice[-1]) == blk_len:
                    # next blk new row
                    block_matrice.append([byte])
                    continue
                # append byte to row
                block_matrice[-1].append(byte)
    return(numpy.array(block_matrice).T)

def block_sample(bstr, keylen, num_blocks):
    blocks = []
    for n in range(0, num_blocks*keylen, keylen):
        if n+keylen > len(bstr):
            print("next block sample outside of cypher length!")
            exit(1)
        blocks += [bstr[n:n+keylen]]
    return(blocks)

def guess_keylen(bstr, keylen, num_blocks):
    blocks = block_sample(bstr, keylen, num_blocks)
    #for n in range(0, num_blocks*keylen, keylen):
    #    blocks += [bstr[n:n+keylen]]
    distances = 0
    avg_distance = 0
    for n in range(0, num_blocks-1):
        # normalize with keylen
        # for bytes(): blocks[n] is already a list!
        avg_distance += hamming(bytes(blocks[n]), bytes(blocks[n+1]))/keylen
        distances += 1
    # actual average distance...
    return(avg_distance/distances)

def char_freq(bstr, num):
    # return num most frequent chars
    return(collections.Counter(bstr).most_common(num))

def break_rep_key_xor(bstr, keyLenLimit):
    hemmings = {}
    for n in range(1, keyLenLimit):
        hemmings[guess_keylen(cypher, n, 40)] = n

    guessed_keys = []
    count = 0
    for h in sorted(hemmings.items()):
        if count == 6:
            break
        blocks = block_sample(cypher, h[1], 90)
        blk_matrice = make_blk_matrice(blocks)

        kbstr = b''
        for l in blk_matrice:
            #kbstr = b''
            lineEnc = b''
            for b in l:
                lineEnc += bytes([b])
            kb = break_1_char_xor(lineEnc, 1, brute=False)
            kbstr += kb

        guessed_keys.append(kbstr)
        count += 1

    return(guessed_keys)

########################################################################

# single char
f1 = open('large_text.txt', 'r')
#f1 = open('6.txt', 'r')

t = f1.readlines()
f1.close()
clear = ""
for l in t:
    clear += l
clear = bytes(clear, 'ascii')

cypher = xor_repeat(clear, b'I', 1)
#clear = xor_repeat(cypher, b'I', 1)

key = break_1_char_xor(cypher, 3)

#clear = xor_repeat(cypher, key, len(key))

#print(clear.decode('ascii'))

######

# more chars


#f1 = open('large_text.txt', 'r')
f1 = open('6.txt', 'r')
f2 = open('out.txt', 'w', newline=None)
t = f1.readlines()

f1.close()
clear = ""
cypher = ""
for l in t:
    cypher += l
cypher = binascii.a2b_base64(cypher)

guessed_keys = break_rep_key_xor(cypher, 30)
for k in guessed_keys:
    clear = xor_repeat(cypher, k, len(k))
    s = ''.join(["For key: {}\n\n".format(k.decode('ascii')), clear.decode('ascii'), "\n\n\n\n"])
    f2.write(s)



"""
hemmings = {}
for n in range(1, 7):
    hemmings[n] = guess_keylen(cypher, n, 40)


blocks = block_sample(cypher, 3, 120)
blk_matrice = make_blk_matrice(blocks)

#print(blk_matrice)

bstr = b''
for l in blk_matrice:
    for b in l:
        bstr += bytes([b])
    print(break_1_char_xor(bstr, 1, brute=False))
    bstr = b''
"""