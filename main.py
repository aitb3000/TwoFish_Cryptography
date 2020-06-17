import json
from typing import Optional

import TwoFish
from DiffieHellman import DH_KeyExchange
from signature import sign, verify


def save_customers_data(data: str):
    """
    Saving into a file the customers data.
    :param data:
    :return:
    """
    with open("data_file.data", "w") as write_file:
        json.dump(data, write_file)


def load_encrypt_file(data_location: Optional[str]):
    if data_location is not None:
        return json.load(data_location)


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

    message = "Hello World"

    print("Message: {}".format(message))

    # Set the key length
    # 128, 196 or 256
    N = 256
    # Default rounds is 16 rounds as the TwoFish paper define to us.
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
