import unittest
from crypto_algos import misc


class TestMisc(unittest.TestCase):

    def testPadPKCS7(self):
        txt = b'12345678123456'
        expected_padded = b'12345678123456\x02\x02'
        padded = misc.padPKCS7(txt, 16)
        self.assertEqual(padded, expected_padded)

    def testUnpadPKCS7(self):
        txt = b'12345678123456\x02\x02'
        expected_unpadded = b'12345678123456'
        unpadded = misc.unpadPKCS7(txt, 16)
        self.assertEqual(unpadded, expected_unpadded)


if __name__ == '__main__':
    unittest.main()
