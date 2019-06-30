import struct
import collections
from crypto_algos.helpers import xorBytestrings

english_letters = ()
english_bigrams = ()


def hammingDistance(bstr1: bytes, bstr2: bytes) -> int:
    """
    Compute Hamming Distance between two strings

    :param bstr1: byte string 1
    :param bstr2: byte string 2
    :return: int
    """
    if len(bstr1) != len(bstr2):
        print("xor not equal len!")
        exit(1)
    diff = b''
    b1 = bstr1
    b2 = bstr2
    diff = xorBytestrings(b1, b2)
    distance = 0
    for b in diff:
        distance += bin(b).count("1")
    return(distance)


def bytesFrequency(bstr: bytes, length: int) -> dict:
    """
    Count the occurences of each distinct group of bytes of length len in bstr

    :param bstr: byte string
    :return: dict mapping bytes to their frequency in bstr
    """
    if length < 0:
        

    #tupels = collections.Counter(bstr).most_common(len(bstr))
    #return {b: f for (b, f) in tupels}


def mapFreqsToLang(dict_bytes_to_freqs: dict, language_tuple: tuple) -> dict:
    """
    Map dictionary (obtained from bytesFrequency) items, i.e. the bytes obtained from
    a byte string, to bytes in the language tuple that have the same frequency in that language.
    The frequency is the key in the dict and the index position in the tuple.

    :param dict_bytes_to_freqs: dict mapping {<occurence in bytestr>: b'foo'}
    :param language_tuple: a tuple with characters, bigrams or trigrams etc.
    They have the same length as the value bytes in the dict.
    Index of a char or group of bytes corresponds to its frequency in the
    language
    :return: dict mapping {b'foo': b'bar'}
    """
    pass