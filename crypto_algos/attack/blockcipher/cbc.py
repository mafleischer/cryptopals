#!/usr/bin/python3


def cipherWFlippedBytesGenerator(bstr_cipher, *indexes):
    """ used for breaking cbc; flip the bytes in the positions given in indexes list """
    # nonsense
    index_to_bytes = tuple( ( (i, b) for i, b in zip(indexes, bstr_cipher[i]) ) )
    for t in index_to_bytes:
