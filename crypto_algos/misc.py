def padPKCS7(bstr_msg, block_size):
    # PKCS5 / PKCS7 padding
    padding_byte = (block_size - len(bstr_msg) % block_size)
    if padding_byte != block_size:
        bstr_msg += bytes([padding_byte]) * padding_byte
    return bstr_msg