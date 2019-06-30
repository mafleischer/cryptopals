import unittest
from crypto_algos.attack.statistics import hammingDistance
from crypto_algos.attack.statistics import bytesFrequency


class TestStatistics(unittest.TestCase):
    def testHammingDistance(self):
        dist = hammingDistance(b'AAB', b'AAC')
        self.assertEqual(dist, 1)

    def testBytesFrequency(self):
        d = bytesFrequency(b'AAAABBB', 1)
        self.assertDictEqual(d, {0x44: 4, 0x45: 3})


if __name__ == '__main__':
    unittest.main()
