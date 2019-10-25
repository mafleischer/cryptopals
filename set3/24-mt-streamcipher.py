#!/usr/bin/python3
from crypto_algos.challenge_specific import mtStreamCipher
if __name__ == '__main__':
    cipher = mtStreamCipher(b'AAAAAAAAAAAA', 1234445)
    print(mtStreamCipher(cipher, 1234445))