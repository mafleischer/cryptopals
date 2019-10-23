import unittest
from crypto_algos import challenge_specific
from crypto_algos.attack.blockcipher import ecb_chosen_plaintext


class TestBlockCipherAttack(unittest.TestCase):
    # def testECBChosenPlaintext(self):
    #    blockcipher.ecbChosenPlaintext()

    def testECBByteOracle(self):
        key = b'1234567812345678'
        # secretmaker uses padding
        secret_fn = challenge_specific.setupECBSecretMaker(
            key, unittest_secret_portion=b'XYZ')
        self.assertEqual(ecb_chosen_plaintext._ecbByteOracle(
            b'AAAAAAAAAAAAAAXY', secret_fn, 2), True)
        secret_fn = challenge_specific.setupECBSecretMaker(
            key, unittest_secret_portion=b'Rollin\' in')
        self.assertEqual(ecb_chosen_plaintext._ecbByteOracle(
            b'xxxxxxRollin\' in', secret_fn, 10), True)



if __name__ == '__main__':
    unittest.main()