import binascii
from crypto_algos import misc, aes


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
        #print(chr(bstr_clear[15]))
        #print(chr(aes.aesEncrypt(bstr_clear, bstr_key, 128, mode='ecb', bstr_IV=None)[15]))
        return aes.aesEncrypt(bstr_clear, bstr_key, 128, mode='ecb', bstr_IV=None)

    return _ecbAppendMakeSecret
