#!/usr/bin/python3

from crypto_algos.prng import MersenneTwister


def _mtUnshiftRight(v: int, shift: int) -> int:
    res = v
    # the right shifts need two times
    res = v ^ res >> shift
    res = v ^ res >> shift
    return  res


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


def mtUntwist(stateArray: list) -> list:
    pass


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