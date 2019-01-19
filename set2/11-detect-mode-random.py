from crypto_algos.attack.blockcipher import ecbmisc

clear = b''
with open("11.txt", 'r') as f:
    txt = f.read()
    clear = bytes(txt, 'ascii')

for n in range(10):
    cipher, mode = ecbmisc.aesRandomEncOracle(clear)
    if ecbmisc.isECB(cipher) and mode != 'ecb' or not ecbmisc.isECB(cipher) and mode == 'ecb':
        print('Fail!')
