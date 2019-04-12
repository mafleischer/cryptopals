#!/usr/bin/python3


def cipherWFlippedBytesGenerator(bstr_cipher, *indexes):
    """ used for breaking cbc; flip the bytes in the positions given in indexes list;
    intended but not used so far
    """
    index_to_bytes = tuple( ( (i, bstr_cipher[i]) for i in indexes ) )
    for tup in index_to_bytes:
    	new_cipher = bstr_cipher
    	yield new_cipher