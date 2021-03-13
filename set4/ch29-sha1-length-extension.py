#!/usr/bin/python3

import struct
from crypto_algos.submodules.sha1.sha1 import sha1
from crypto_algos.attack.hash import sha1 as attacksha1

if __name__ == "__main__":
    # print(SHA1Padding(b'a'))
    key = b"secret"
    clear = b"bla"
    clear = (
        b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    )
    # forge = b"a"
    forge = b";admin=true"

    h = bytes(sha1(key + clear), "ascii")

    regs = attacksha1.SHA1RegistersFromHash(h)

    # ofc normally you don't know the key and you would guess the padding
    padding = attacksha1.SHA1Padding(clear, len(key))
    le = attacksha1.Sha1LengthExtension(regs, len(key + clear + padding))

    new_hash = le.update(forge).hexdigest()
    print("Length extension hash: {}".format(new_hash))

    h = sha1(key + clear + padding + forge)
    print(
        "Extension control hash (hash: key + clear + old padding + forge string): {}".format(
            h
        )
    )
