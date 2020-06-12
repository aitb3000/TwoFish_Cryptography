import base64

from KeyExchange.DiffieHellman import DH_KeyExchange
from TwoFish import TwoFish

if __name__ == '__main__':
    """
    1) Alice = KeyExchange -> Return A
    2) Bob = KeyExchange -> Return B

    3) Bob use - new_pear -> Get A (This will calculate the K)
    4) Alice use - new_pear -> Get B (This will calculate the K)

    5) Alice encrypt using the K from new_peer via TwoFish.
    6) Bob encrypt using the K from new_peer via TwoFish.

    7) Alice dec using the K from new_peer via TwoFish.
    8) Bob dec using the K from new_peer via TwoFish.
    """

    # set the key
    alice = DH_KeyExchange()
    bob = DH_KeyExchange()

    # Alice send the A to Bob and Generate K
    bob.new_peer(alice.public)
    # Bob send the B to Alice and Generate K
    alice.new_peer(bob.public)

    # K to encrpy the Message
    alice_key = alice.peers.values()
    bob_key = bob.peers.values()
    # alice_key = str(base64.b64encode((str(alice.public)).encode("utf-8")))
    # bob_key = str(base64.b64encode((str(alice.public)).encode("utf-8")))

    # Set the key length
    N = 256
    rounds = 16

    # Generate Key and ... - TwoFish
    [K, S] = TwoFish.gen_keys(str(alice_key), N, rounds)

    message = 'Hello World'
    print("Message: {}".format(message))

    # Alice encrypt plaintext
    [num_C, Cypher_text] = TwoFish.encrypt_message(message, S, K, rounds=16)
    print("Enc Message: {}".format(Cypher_text))

    # Bob want to know the message
    # Generate Key and ... - TwoFish
    [K, S] = TwoFish.gen_keys(str(bob_key), N, rounds)

    plain_text = TwoFish.decrypt_message(num_C, S, K, rounds=16)

    print(plain_text)

    # try key reversal

    # test_text = encrypt_message(Cypher_text, S[::-1], K[::-1])

    # print('++++++++++')
    # print(test_text)