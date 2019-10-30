import unittest
import numpy as np
import base64
from crypto_algos import aes
from crypto_algos import exceptions


class TestAESEncrypt(unittest.TestCase):

    def setUp(self):
        self.bstr_teststate = b'\x19\xa0\x9a\xe9\x3d\xf4\xc6\xf8\xe3\xe2\x8d\x48\xbe\x2b\x2a\x08'

    def testAESAddRoundkey(self):
        k1 = np.array([[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 1, 0]])
        k2 = np.array([[1, 1, 1, 1], [1, 1, 1, 1], [1, 1, 1, 1], [1, 1, 1, 1]])
        expected = np.array([[1, 1, 1, 1], [1, 1, 1, 1],
                             [1, 1, 1, 1], [1, 1, 0, 1]])
        k1 = bytes(k1.flatten())
        k2 = bytes(k2.flatten())
        expected = bytes(expected.flatten())
        result = aes.aesAddRoundkey(k1, k2)
        self.assertEqual(expected, result)

    def testAESSubBytes(self):
        #k = b'\x00\x00\x00\x00\x00\x00\x01\x00'
        #expected = b'\x63\x63\x63\x63\x63\x63\x7c\x63'
        bstr_teststate = b'\x19\xa0\x9a\xe9\x3d\xf4\xc6\xf8\xe3\xe2\x8d\x48\xbe\x2b\x2a\x08'
        expected = b'\xd4\xe0\xb8\x1e\x27\xbf\xb4\x41\x11\x98\x5d\x52\xae\xf1\xe5\x30'
        result = aes.aesSubBytes(bstr_teststate)
        self.assertEqual(result, expected)

    def testAESKeyExpansion(self):
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        rk1_expected = bytes.fromhex('a0fafe1788542cb123a339392a6c7605')
        rk2_expected = bytes.fromhex('f2c295f27a96b9435935807a7359f67f')
        round_keys = aes.aesKeyExpansion(key)
        self.assertEqual(len(round_keys), 10)
        self.assertEqual(round_keys[0], rk1_expected)
        self.assertEqual(round_keys[1], rk2_expected)

    def testAESShiftRows(self):
        #state = bytes(np.array([1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4], dtype=np.uint8))
        #state_expected = np.array([[1,2,3,4], [2,3,4,1], [3,4,1,2], [4,1,2,3]])
        bstr_teststate = b"\xd4\xe0\xb8\x1e\x27\xbf\xb4\x41\x11\x98\x5d\x52\xae\xf1\xe5\x30"
        expected = b"\xd4\xe0\xb8\x1e\xbf\xb4\x41\x27\x5d\x52\x11\x98\x30\xae\xf1\xe5"
        result = aes.aesShiftRows(bstr_teststate)
        #state = aes.make_ndarray_from(state, 4, 4)
        self.assertEqual(result, expected)

    def testAESMixColumns(self):
        bstr_teststate = b"\xd4\xe0\xb8\x1e\xbf\xb4\x41\x27\x5d\x52\x11\x98\x30\xae\xf1\xe5"
        expected = b'\x04\xe0\x48\x28\x66\xcb\xf8\x06\x81\x19\xd3\x26\xe5\x9a\x7a\x4c'
        result = aes.aesMixColumns(bstr_teststate)
        self.assertEqual(result, expected)

    def testAESEnryptECB(self):
        #key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        #data = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
        #cipher_expected = b'9%\x84\x1d\x02\xdc\t\xfb\xdc\x11\x85\x97\x19j\x0b2'
        #cipher = aes.aesEncrypt(data, key, 128)
        #self.assertEqual(cipher, cipher_expected)
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        data = bytes.fromhex('00112233445566778899aabbccddeeff')
        cipher_expected = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
        cipher = aes.aesEncrypt(data, key, 128)
        self.assertEqual(cipher, cipher_expected)

    def testAESEnryptCBC(self):
        #key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        #data = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
        #cipher_expected = b'9%\x84\x1d\x02\xdc\t\xfb\xdc\x11\x85\x97\x19j\x0b2'
        #cipher = aes.aesEncrypt(data, key, 128)
        #self.assertEqual(cipher, cipher_expected)
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        data = bytes.fromhex('00112233445566778899aabbccddeeff')
        cipher_expected = b'|\x99\xf4+n\xe5\x030\x9cl\x1ag\xe9z\xc2B'
        IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff'
        cipher = aes.aesEncrypt(data, key, 128, mode='cbc', bstr_IV=IV)
        self.assertEqual(cipher, cipher_expected)


class TestAESDecrypt(unittest.TestCase):

    def testAESInvSubBytes(self):
        #k = b'\x00\x00\x00\x00\x00\x00\x01\x00'
        #expected = b'\x63\x63\x63\x63\x63\x63\x7c\x63'
        expected = b'\x19\xa0\x9a\xe9\x3d\xf4\xc6\xf8\xe3\xe2\x8d\x48\xbe\x2b\x2a\x08'
        bstr_teststate = b'\xd4\xe0\xb8\x1e\x27\xbf\xb4\x41\x11\x98\x5d\x52\xae\xf1\xe5\x30'
        result = aes.aesInvSubBytes(bstr_teststate)
        self.assertEqual(result, expected)

    def testAESInvShiftRows(self):
        #state = bytes(np.array([1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4], dtype=np.uint8))
        #state_expected = np.array([[1,2,3,4], [2,3,4,1], [3,4,1,2], [4,1,2,3]])
        expected = b"\xd4\xe0\xb8\x1e\x27\xbf\xb4\x41\x11\x98\x5d\x52\xae\xf1\xe5\x30"
        bstr_teststate = b"\xd4\xe0\xb8\x1e\xbf\xb4\x41\x27\x5d\x52\x11\x98\x30\xae\xf1\xe5"
        result = aes.aesInvShiftRows(bstr_teststate)
        #state = aes.make_ndarray_from(state, 4, 4)
        self.assertEqual(result, expected)

    def testAESInvMixColumns(self):
        expected = b"\xd4\xe0\xb8\x1e\xbf\xb4\x41\x27\x5d\x52\x11\x98\x30\xae\xf1\xe5"
        bstr_teststate = b'\x04\xe0\x48\x28\x66\xcb\xf8\x06\x81\x19\xd3\x26\xe5\x9a\x7a\x4c'
        result = aes.aesInvMixColumns(bstr_teststate)
        self.assertEqual(result, expected)

    def testAESDecryptECB(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        clear_expected = bytes.fromhex('00112233445566778899aabbccddeeff')
        cipher = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
        clear = aes.aesDecrypt(cipher, key, 128)
        self.assertEqual(clear, clear_expected)

    def testAESDecryptCBC(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        clear_expected = bytes.fromhex('00112233445566778899aabbccddeeff')
        cipher = b'|\x99\xf4+n\xe5\x030\x9cl\x1ag\xe9z\xc2B'
        IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff'
        clear = aes.aesDecrypt(cipher, key, 128, mode='cbc', bstr_IV=IV)
        self.assertEqual(clear, clear_expected)

class TestAESCTR(unittest.TestCase):

    def testAESCTREncrypt(self):
        cipher = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
        key = b'YELLOW SUBMARINE'
        nonce = bytes(8)
        clear = aes.aesCTR(cipher, key, 128, nonce)
        self.assertEqual(clear, b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")

    def testAESCTREdit(self):
        key = b'x' * 16
        nonce = b'y' * 8

        res = aes.aesCTR(b'1234567812345678', key, 128, nonce)
        cipher = bytearray(res)
        edit = aes.aesCTREdit(cipher, key, nonce, 128, 0, b'X')
        clear = aes.aesCTR(cipher, key, 128, nonce)
        self.assertEqual(clear, b'X234567812345678')

        cipher = bytearray(res)
        edit = aes.aesCTREdit(cipher, key, nonce, 128, 0, b'XY')
        clear = aes.aesCTR(cipher, key, 128, nonce)
        self.assertEqual(clear, b'XY34567812345678')

        cipher = bytearray(res)
        edit = aes.aesCTREdit(cipher, key, nonce, 128, 1, b'XY')
        clear = aes.aesCTR(cipher, key, 128, nonce)
        self.assertEqual(clear, b'1XY4567812345678')

        cipher = bytearray(res)
        self.assertRaises(exceptions.ParamClashError, aes.aesCTREdit, cipher,
                          key, nonce, 128, 15, b'XY')

        # over more than one block
        cipher = aes.aesCTR(b'1234567812345678' * 2, key, 128, nonce)
        cipher = bytearray(cipher)
        edit = aes.aesCTREdit(cipher, key, nonce, 128, 0, b'X' * 31)
        clear = aes.aesCTR(cipher, key, 128, nonce)
        self.assertEqual(clear, b'X' * 31 + b'8')


if __name__ == '__main__':
    unittest.main()