#!/usr/bin/python3

import random
import time

from crypto_algos.challenge_specific import mtStreamCipher, encMTWithRndPrefix
from crypto_algos.attack.prng import crackMTSeedKnownPlain, hasTokenCurrentTimeSeed
from crypto_algos.helpers import xorBytestrings

if __name__ == '__main__':
    cipher = mtStreamCipher(b'AAAAAAAAAAAA', 1234445)
    print(mtStreamCipher(cipher, 1234445))
    cipher = encMTWithRndPrefix(b'sdfsdflkdsfjdsafdsa', 123345766)
    print(mtStreamCipher(cipher, 123345766))

    known_plain = b'A' * 16
    seed = random.randint(1,6000000)
    cipher = encMTWithRndPrefix(known_plain, seed)
    seed_recovered = crackMTSeedKnownPlain(cipher, known_plain,
                                           len(cipher) - len(known_plain), 8, 16)
    print('Recovered seed: {}'.format(seed_recovered))
    print(mtStreamCipher(cipher, seed_recovered))

    # second part of ch. 24
    current_time = int(time.time())
    mt = random.Random(current_time)
    token = mt.getrandbits(32)
    time_range = (-100, 100)
    if hasTokenCurrentTimeSeed(token,time_range):
        print('Token has current time seed.')
    else:
        print('Token does not have current time seed.')