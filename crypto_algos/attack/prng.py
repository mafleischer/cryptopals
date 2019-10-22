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


def tapMTFor624(mt: MersenneTwister) -> list:
    pass


def mtCloneFromOutput(output_list: list) -> MersenneTwister:
    mt = MersenneTwister()
    for state in output_list:
        mt.state.append(state)
    return mt