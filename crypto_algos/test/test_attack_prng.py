import unittest
import random
from crypto_algos.attack.prng import mtWithStateFromList


class TestHelpers(unittest.TestCase):

    def testMTWithStateFromList(self):
        seed = 123345678
        random.seed(seed)
        output_list = []
        for i in range(624):
            output_list.append(random.getrandbits(32))

        rn_python = random.getrandbits(32)
        mt = mtWithStateFromList(output_list)
        rn_my = mt.get_random_number()
        self.assertEqual(rn_my, rn_python)
