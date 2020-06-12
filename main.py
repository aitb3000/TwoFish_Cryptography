import base64

from KeyExchange.DiffieHellman import KeyExchange
from TwoFish import TwoFish

if __name__ == '__main__':
    # set the key
    alice = KeyExchange()
    key = str(base64.b64encode((str(alice.secret)).encode("utf-8")))
    # set the key length
    N = 256
    rounds = 16

    [K, S] = TwoFish.gen_keys(str(key), N, rounds)

    test = 'hello there,this is a test of how well I can encrypt things and all that jazz. Did it work?'
    # test = 'hello there, this is a test'

    [num_C, Cypher_text] = TwoFish.encrypt_message(test, S, K, rounds=16)

    print(Cypher_text)

    plain_text = TwoFish.decrypt_message(num_C, S, K, rounds=16)

    print(plain_text)

    # try key reversal

    # test_text = encrypt_message(Cypher_text, S[::-1], K[::-1])

    # print('++++++++++')
    # print(test_text)