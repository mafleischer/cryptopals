

def SHA1Padding(bstr: bytes) -> bytes:
    processed = bstr + b'\x80'
    padding = b'\x00' * ((56 - (len(processed)) % 64) % 64)
    msg_bit_len = len(bstr) * 8
    return processed + padding + struct.pack(b'>Q', msg_bit_len)


def SHA1RegistersFromHash(bstr_hash: bytes) -> list:
    regs = []
    for i in range(5):
        regs.append(bstr_hash[i*32 : i*32 + 32])
    return regs