#!/usr/bin/python3

import random

from crypto_algos.challenge_specific import mtStreamCipher, encMTWithRndPrefix
from crypto_algos.attack.prng import crackMTSeedKnownPlain
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