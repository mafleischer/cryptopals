import struct
import collections
from crypto_algos import RESOURCES_DIR_NAME
from crypto_algos.exceptions import ParamValueError, ParamClashError
from crypto_algos.helpers import xorBytestrings, stateGenerator, substituteBytes


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
    return (distance)


def bytesFrequency(bstr: bytes, length: int) -> tuple:
    """
    Count the occurences of each distinct group of bytes of length len in bstr

    :param bstr: byte string
    :return: dict mapping bytes to their frequency in bstr
    """
    if length < 0:
        raise ParamValueError
    if length > len(bstr):
        raise ParamClashError
    state_iter = stateGenerator(bstr, length, modis0=False)
    groups = tuple(bytes(state) for state in state_iter)
    num_groups = len(bstr) // length
    # throw away remainder since it doesn't have length <length>
    if len(groups) > num_groups:
        groups = groups[:-1]
    tupels = collections.Counter(groups).most_common(num_groups)
    return tuple(b for (b, _) in tupels)


def getNgramsFromFile(length: int, lang: str) -> tuple:
    """
    Read Ngrams (monograms, bigrams etc. So far only mono and bigrams)
    from file, frequency in descending order.
    :param length: length, translates to file name
    :return: tuple containg Ngrams
    """
    if length == 1:
        fname = lang + '_monograms.txt'
    if length == 2:
        fname = lang + '_bigrams.txt'

    with open(RESOURCES_DIR_NAME + fname) as f:
        lines = f.readlines()
    ngrams = tuple(line.split(' ')[0].encode('ascii') for line in lines)
    if length == 1:
        # space is the most frequent monogram actually, duh
        ngrams = (b' ',) + ngrams
    return ngrams


def mapFreqBytes2FreqLang(freq_bytes: tuple, language_tuple: tuple, top_n: int = None) -> dict:
    """
    NOT USED CURRENTLY!
    Map tuple (obtained from bytesFrequency), i.e. the bytes obtained from
    a byte string, to bytes in the language tuple that have the same frequency in that language.
    The frequency corresponds to the index position in the tuples.

    :param freq_bytes: dict mapping {<occurrence in bytestr>: b'foo'}
    :param language_tuple: a tuple with characters, bigrams or trigrams etc.
    They have the same length as the bytes in the first tuple.
    Index of a char or group of bytes corresponds to its frequency in the
    language
    ::
    :return: dict mapping {b'foo': b'bar'}
    """
    if top_n is None:
        return dict(zip(freq_bytes, language_tuple))
    return dict(zip(freq_bytes[:top_n], language_tuple))


def substituteLangNgramsIn(bstr: bytes, lang: str, length: int, top_n: int = None) -> bytes:
    """
    Actual language frequency workhorse. Substitute byte groups of length length
    in bstr according to the frequency of mono or bigrams etc. of language lang
    TODO: write case for words as ngrams

    :param bstr: byte string
    :param lang: language abbreviated (en = english, etc.)
    :param length: int, 1 = monograms etc.
    :param top_n: only substitute for n most frequent ngrams. If none substitute as many as
    possible
    :return: byte string
    """
    current_bytes = bytesFrequency(bstr, length)
    ngrams = getNgramsFromFile(length, lang)
    if not top_n:
        current_bytes = current_bytes[:top_n]
        ngrams = ngrams[:top_n]
    return substituteBytes(bstr, current_bytes, ngrams)
