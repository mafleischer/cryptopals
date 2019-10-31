import binascii
import os
import random
import time
import urllib.parse
from crypto_algos import misc, aes, logger
from crypto_algos.prng import MersenneTwister
from crypto_algos.helpers import xorBytestrings


def setupECBSecretMaker(bstr_key, unittest_secret_portion=None):
    """
    challenge 12
    """
    to_crack_b64 = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK""".replace('\n', '')
    to_crack = binascii.a2b_base64(to_crack_b64)
    #to_crack = b'Rollin\' in'

    if unittest_secret_portion:
        to_crack = unittest_secret_portion

    def _ecbAppendMakeSecret(bstr_chosen):
        """
        give clear input and append unkown clear string (to be cracked) before encrypting
        """
        blocksize = 16
        bstr_clear = misc.padPKCS7(bstr_chosen + to_crack, blocksize)
        # print(bstr_clear)
        # print(chr(bstr_clear[15]))
        #print(chr(aes.aesEncrypt(bstr_clear, bstr_key, 128, mode='ecb', bstr_IV=None)[15]))
        return aes.aesEncrypt(bstr_clear, bstr_key, 128, mode='ecb', bstr_IV=None)

    return _ecbAppendMakeSecret


def setupECBSecretMakerPrepend(bstr_key, unittest_secret_portion=None):
    """
    challenge 14
    """
    to_crack_b64 = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK""".replace('\n', '')
    to_crack = binascii.a2b_base64(to_crack_b64)
    to_crack = b'abcd'
    #to_crack = b'Rollin\' in'

    if unittest_secret_portion:
        to_crack = unittest_secret_portion

    def _ecbAppendMakeSecret(bstr_chosen):
        """
        give clear input and append unkown clear string (to be cracked) and prepend
        random number of random bytes to input before encrypting
        """
        blocksize = 16
        bstr_prefix = os.urandom(random.randint(5, 38))
        bstr_clear = misc.padPKCS7(
            bstr_prefix + bstr_chosen + to_crack, blocksize)
        return aes.aesEncrypt(bstr_clear, bstr_key, 128, mode='ecb', bstr_IV=None)

    return _ecbAppendMakeSecret


def setupCBCSecretMaker(bstr_key, bstr_IV):
    """
    challenge 16
    """
    bstr_prefix = b'comment1=cooking%20MCs;userdata='
    bstr_suffix = b';comment2=%20like%20a%20pound%20of%20bacon'

    def _cbcAppendMakeSecret(bstr_chosen):
        blocksize = 16
        #bstr_urlencoded_chosen = bytes(urllib.parse.quote_plus(bstr_chosen), 'ascii')
        bstr_urlencoded_chosen = bstr_chosen
        bstr_clear = misc.padPKCS7(
            bstr_prefix + bstr_urlencoded_chosen + bstr_suffix, blocksize)
        return aes.aesEncrypt(bstr_clear, bstr_key, 128, mode='cbc', bstr_IV=bstr_IV)

    return _cbcAppendMakeSecret


def setupCTRSecretMaker(bstr_key, bstr_nonce):
    """
    challenge 16
    """
    bstr_prefix = b'comment1=cooking%20MCs;userdata='
    bstr_suffix = b';comment2=%20like%20a%20pound%20of%20bacon'

    def _ctrAppendMakeSecret(bstr_chosen):
        blocksize = 16
        #bstr_urlencoded_chosen = bytes(urllib.parse.quote_plus(bstr_chosen), 'ascii')
        bstr_urlencoded_chosen = bstr_chosen
        bstr_clear = misc.padPKCS7(
            bstr_prefix + bstr_urlencoded_chosen + bstr_suffix, blocksize)
        return aes.aesCTR(bstr_clear, bstr_key, 128, bstr_nonce)

    return _ctrAppendMakeSecret


class InvalidPKCS7Error(Exception):
    """Set 3/Ch. 17"""
    pass


def hasValidPKCS7(bstr, blocksize):
    """Set 2/Ch.15;
    check if it has valid pkcs7 padding """
    last_byte = bstr[-1]
    padding = bstr[-last_byte:]
    if not padding.count(last_byte) == last_byte:
        raise InvalidPKCS7Error
    if last_byte == blocksize:
        return None

def makeCBCPaddingOracle(key, IV):
    """Set 3/Ch. 17"""
    def _cbcPaddingOracle(bstr_cipher):
        plain = aes.aesDecrypt(bstr_cipher, key, 128, mode='cbc', bstr_IV=IV)
        try:
            hasValidPKCS7(plain, 16)
        except InvalidPKCS7Error:
            raise
        else:
            return None
    return _cbcPaddingOracle

def mtSeedWithTimeStamp() -> int:
    """
    Set 3 / Ch. 22
    :return: random number
    """
    seconds_range = (1, 21)
    wait_seconds = random.randint(seconds_range[0], seconds_range[1])
    time.sleep(wait_seconds)
    mt = MersenneTwister(int(time.time()))
    wait_seconds = random.randint(seconds_range[0], seconds_range[1])
    time.sleep(wait_seconds)
    return mt.get_random_number()


def mtStreamCipher(bstr_msg: bytes, seed: int) -> bytes:
    """
    set 3 / ch. 24, en/decrypt with keystream generated from
    MT random 8 bit numbers
    :param bstr_msg:
    :param seed: seed that will be converted to 16 bit (xored with 0xFFFF)
    :return:
    """
    # 16 bit seed
    random.seed(seed & 0xFFFF)
    keystream = b''
    for i in range(len(bstr_msg)):
        rnum = random.getrandbits(8)
        keystream += bytes([rnum])
    return xorBytestrings(bstr_msg, keystream)


def encMTWithRndPrefix(bstr_msg: bytes, seed: int) -> bytes:
    """
    set 3 / ch. 24 use mtStreamCipher and prepend chars before
    :param bstr_msg:
    :param seed:
    :return:
    """
    mt = random.Random()
    numchars = mt.randint(1, 50)
    pre = b'x' * numchars
    return mtStreamCipher(pre + bstr_msg, seed)