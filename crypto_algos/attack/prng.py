#!/usr/bin/python3

import random
from crypto_algos.prng import MersenneTwister
from crypto_algos.helpers import xorBytestrings


def _mtUnshiftRight(v: int, shift: int) -> int:
    res = v
    # the right shifts need two times
    res = v ^ res >> shift
    res = v ^ res >> shift
    return res


def _mtUnshiftLeft(v: int, shift: int, mask: int) -> int:
    res = v
    # s = 7 bit shift needs four times at least to be reversed
    for i in range(4):
        res = v ^ res << shift & mask
    return res


def mtUntemper(randNum: int) -> int:
    mt = MersenneTwister()
    res = _mtUnshiftRight(randNum, mt.l)
    res = _mtUnshiftLeft(res, mt.t, mt.c)
    res = _mtUnshiftLeft(res, mt.s, mt.b)
    res = _mtUnshiftRight(res, mt.u)
    return res


def tapMTForValues(mt: MersenneTwister, num=624) -> list:
    output_list = []
    for i in range(624):
        rnum = mt.get_random_number()
        output_list.append(rnum)


def mtWithStateFromList(output_list: list) -> MersenneTwister:
    """
    Takes a list of observed outputs from a MT and creates a
    new MT with untempered values from output_list as its state
    values
    :param output_list: (min) 624 output values from a MT
    :return: MersenneTwister object
    """
    mt = MersenneTwister()
    mt.state.clear()
    mt.state = [mtUntemper(rnum) for rnum in output_list]
    mt.index = 624
    return mt


def crackMTSeedKnownPlain(bstr_cipher: bytes, bstr_known_plain: bytes,
                          offset: int, bits: int, seed_bits: int) -> int:
    """
    From a known plaintext recover the seed
    :param bstr_cipher:
    :param bstr_known_plain:
    :param offset: the known plain text starts at this position in the cipher text
    (ch. 24 prepends random known text)
    :param bits: number of bits to get from MT
    :param seed_bits: number of bits of the seed
    :return: recovered seed
    """

    known_plain_cipher = bstr_cipher[offset: offset + len(bstr_known_plain)]
    for seed in range(2 ** seed_bits):
        random.seed(seed)
        # construct key
        keystream = b''
        # fast forward to the proper point in the MT sequence
        for _ in range(offset):
            random.getrandbits(bits)
        for i in range(len(bstr_known_plain)):
            keystream += bytes([random.getrandbits(bits)])
        plain = xorBytestrings(known_plain_cipher, keystream)
        if plain == bstr_known_plain:
            return seed