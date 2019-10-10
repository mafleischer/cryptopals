from crypto_algos.prng import MersenneTwister

if __name__ == "__main__":
    #rng = mersenne_rng(1131464071)
    rng = MersenneTwister(1570732518)
    for i in range(10):
        print(rng.get_random_number())