#!/usr/bin/python3

import random

from crypto_algos.attack.prng import mtWithStateFromList, mtUntemper
from crypto_algos.prng import MersenneTwister

mt = MersenneTwister(1234445)

output_list = []
for i in range(624):
    rn = mt.get_random_number()
    output_list.append(rn)


print(mt.get_random_number())
mt = mtWithStateFromList(output_list)
print(mt.get_random_number())