import sys

from KeyExchange.DiffieHellman import DH_KeyExchange
from Signature.signature import sign, verify
from TwoFish import TwoFish
import uuid


def save_customers_data(data: str):
    """
    Saving into a file the customers data.
    :param data:
    :return:
    """
    with open("customer_data.data", 'w') as f:
        f.write(data)


if __name__ == '__main__':
    """
    Bob will encrypt and Alice will decrypt
    -------------------------------------------
    
    1) Alice = KeyExchange -> Return A
    2) Bob = KeyExchange -> Return B
    
    3) Bob use - new_pear -> Get A (This will calculate the K)
    4) Alice use - new_pear -> Get B (This will calculate the K)

    5) Bob generate a Digital Signature via his Private Key with the original Plaintext.
    6) Bob encrypt using the K from new_peer via TwoFish.

    7) Alice decrypt the cypher text using the K from new_peer via TwoFish.
    8) Alice generate a Digital Signature via his Private Key with the decrypt text.
    9) Verify the Signature by comparing the Digest between plaintext and message. 
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

    message = 'Hello World'
    print("Message: {}".format(message))

    # Set the key length
    N = 256
    rounds = 16

    # Generate Key and ... - TwoFish
    [K, S] = TwoFish.gen_keys(str(bob_key), N, rounds)

    bob_sig_key = (str((K[:1])[0]).encode('utf-8')).zfill(16)
    # Digital Signature
    bob_digest = sign(message, bob_sig_key)
    # Alice encrypt plaintext
    [num_C, Cypher_text] = TwoFish.encrypt_message(message, S, K, rounds=16)
    print("Enc Message: {}\n Bob digest {}".format(Cypher_text, bob_digest))

    # Alice want to know the message
    # Generate Key and ... - TwoFish
    [K, S] = TwoFish.gen_keys(str(alice_key), N, rounds)
    plain_text = TwoFish.decrypt_message(num_C, S, K, rounds=16)
    alice_sig_key = (str((K[:1])[0]).encode('utf-8')).zfill(16)
    signature_status = verify(plain_text, alice_sig_key, bob_digest)

    if signature_status:
        print(plain_text)
    else:
        print("Failed")
