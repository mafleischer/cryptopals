from crypto_algos.attack.blockcipher import ecbmisc
from crypto_algos import logger
import os


def findCipherBlockJumpLen(secret_fn):
    """
    find the length len of the chosen plaintext string that causes the cipher length in blocks to be increased by one.
    return len - 1: that is the length of the chosen plain where no padding was applied
    """
    cipher = secret_fn(b'')
    len_cipher = len(cipher)
    add = b'x'
    len_added = len(add)
    for i in range(15):
        len_with_added = len(secret_fn(add))
        if len_cipher < len_with_added:
            return len_added - 1
        else:
            len_added += 1
            add += b'x'