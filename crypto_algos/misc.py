import os
import binascii
from crypto_algos import aes


class Secret:
    """
    Simulate a secret for challenge 12: chosen plaintext, byte by byte decryption
    """
    __to_crack_b64 = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
	    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
	    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK""".replace('\n', '')
    __to_crack = b''

    def __init__(self, bstr_chosen_plain):
        self.__key = os.urandom(16)
        self.__to_crack = binascii.a2b_base64(self.__to_crack_b64)
        self.__cipher = self.makeSecret(bstr_chosen_plain)

    def _ecbAppendedClearEncrypt(self, bstr_input, bstr_append, key, bits=128):
        """
        give clear input and append unkown clear string (to be cracked) before encrypting
        """
        blocksize = 16
        bstr_clear = padPKCS7(bstr_input + bstr_append, blocksize)
        return aes.aesEncrypt(bstr_clear, key, 128, mode='ecb', bstr_IV=None)

    def makeSecret(self, bstr_chosen_plain):
        return self._ecbAppendedClearEncrypt(bstr_chosen_plain, self.__to_crack, self.__key)


def padPKCS7(bstr_msg, block_bytenum):
    # PKCS5 / PKCS7 padding
    padding_byte = (block_bytenum - len(bstr_msg) % block_bytenum)
    if padding_byte != block_bytenum:
        bstr_msg += bytes([padding_byte]) * padding_byte
    return bstr_msg


def unpadPKCS7(bstr_msg):
    pass
