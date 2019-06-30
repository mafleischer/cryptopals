import unittest
from crypto_algos import helpers


class TestHelpers(unittest.TestCase):

    def testStateGenerator(self):
        bytenum = 16
        bstr_msg = b'1234123412341234abcdabcdabcdabcd'
        stategen = helpers.stateGenerator(bstr_msg)
        count = 0
        states = []
        for s in stategen:
            states.append(s)
        self.assertEqual(len(states), len(bstr_msg) / bytenum)
        self.assertEqual(states[0], b'1234123412341234')
        self.assertEqual(states[1], b'abcdabcdabcdabcd')

    def testXorBytestrings(self):
        bstr1 = b'\x01\x01\x01\x01\x01\x01\x01\x01'
        bstr2 = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        result = helpers.xorBytestrings(bstr1, bstr2)
        self.assertEqual(result, b'\x01\x01\x01\x01\x01\x01\x01\x01')
        self.assertEqual(helpers.xorBytestrings(b'A', b'A'), b'\x00')

    def testRotateList(self):
        l = [1, 2, 3, 4]
        ll = helpers.rotateList(l, 2, 'l')
        lr = helpers.rotateList(l, 3, 'r')
        self.assertEqual(ll, [3, 4, 1, 2])
        self.assertEqual(lr, [2, 3, 4, 1])


if __name__ == '__main__':
    unittest.main()