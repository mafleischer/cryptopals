#!/usr/bin/python3

import time
import random
from crypto_algos.challenge_specific import mtSeedWithTimeStamp
from crypto_algos.prng import MersenneTwister

if __name__ == '__main__':
    ts_start = int(time.time())
    to_crack_num = mtSeedWithTimeStamp()
    print("Random number to get seed from: {}".format(to_crack_num))
    ts_stop = int(time.time())
    for ts in range(ts_start, ts_stop):
        mt = MersenneTwister(ts)
        num = mt.get_random_number()
        if num == to_crack_num:
            print("Seed is {}".format(ts))
            exit(0)