import struct
from crypto_algos.submodules.sha1.sha1 import Sha1Hash


def SHA1Padding(bstr: bytes, keylen: int) -> bytes:
    """
    Compute and return the SHA1 padding to bstr

    :param bstr:
    :return:
    """
    padding = b"\x00" * ((56 - (keylen + len(bstr + b"\x80")) % 64) % 64)
    msg_bit_len = (keylen + len(bstr)) * 8
    return b"\x80" + padding + struct.pack(b">Q", msg_bit_len)


def SHA1RegistersFromHash(bstr_hash: bytes) -> tuple:
    regs = tuple()
    for i in range(5):
        st = bstr_hash[i * 8 : i * 8 + 8]
        regs += (int(st, base=16),)
    return regs


class Sha1LengthExtension(Sha1Hash):
    def __init__(self, tup, old_msg_len):
        super().__init__()
        self._h = tup
        self._message_byte_length = old_msg_len
