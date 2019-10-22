#!/usr/bin/python3

from crypto_algos.attack.prng import mtUntemper
from crypto_algos.prng import MersenneTwister

mt = MersenneTwister(1234445)

rn = mt.get_random_number()

rn = mtUntemper(rn)
print(rn)