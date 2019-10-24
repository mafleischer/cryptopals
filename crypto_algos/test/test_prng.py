import unittest
import random
from crypto_algos.prng import MersenneTwister

class TestMersenneTwister(unittest.TestCase):

    def testMersenneTwister(self):
        seed = 123456789
        mt = MersenneTwister(seed)
        rn_my = mt.get_random_number()
        print(mt.state)
        random.seed(seed)
        random.setstate((3, tuple(mt.state + [0]), None))
        rn_python = random.getrandbits(32)
        self.assertEqual(rn_my, rn_python)