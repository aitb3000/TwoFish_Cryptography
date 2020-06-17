from decimal import *
import random
import base64

"""
Example Diffie-Hellman key exchange class in Python
This relies on the difficulty of factoring the discrete logarithm. That is, it is difficult to solve for x in this equation:
ax mod p
particularly when p, a and x are large.
"""

# The precision
getcontext().prec = 100000


class DH_KeyExchange:
    def __init__(self):
        """
        self.secret = Private key (a or b).
        self.n = P (mod)
        self.base = g
        self.public = A or B
        """
        self.P = Decimal(
            '1340185579782030309029142285845485748073406778702270938755484147318382420338087834406828955714187005654640257038495796545155402280055987076251704557994637589726712709889312042801858044039590155407650471667907995888292123909278046563998441725881316702608454953284969473141146885140822683049274853701491')
        self.g = Decimal(
            '14759984361802021245410475928101669395348791811705709117374129427051861355011151') * Decimal(
            '5915587277') % self.P

        # Secret is the private key.
        self.secret = Decimal(random.randrange(11, self.g))
        self.public = modpow(self.g, self.secret, self.P)
        self.peers = dict()

    def new_secret(self):
        self.secret = Decimal(random.randrange(11, self.g))
        self.public = modpow(self.g, self.secret, self.P)

    def new_peer(self, peer_public):
        """
        This calculate the K.
        :param peer_public:
        :return:
        """
        self.peers[peer_public] = modpow(peer_public, self.secret, self.P)


def modpow(b, e, m):
    """
    Calculate A or B (on the picture)
    or
    Calculate K
    :param b:
    :param e:
    :param m:
    :return:
    """
    if m == 1:
        return 0
    result = 1
    base = b % m
    while e > 0:
        if e % 2 == 1:
            result = result * base % m
        e = Decimal(int(e) >> 1)
        base = base * base % m
    return result


if __name__ == "__main__":
    import base64

    alice = DH_KeyExchange()
    with open("KeyExchange/aliceprivate.pem", 'w') as f:
        f.write(str(base64.b64encode((str(alice.secret)).encode("utf-8"))))

    print("alice's public key':", str(base64.b64encode((str(alice.secret)).encode("utf-8"))))

    bob = DH_KeyExchange()
    with open("KeyExchange/bobprivate.pem", 'w') as f:
        f.write(str(base64.b64encode((str(bob.secret)).encode('utf-8'))))

    print("bob's public key':", str(base64.b64encode((str(bob.secret)).encode('utf-8'))))
    bob.new_peer(alice.public)
    alice.new_peer(bob.public)
    print(alice.peers.values(), "\n", bob.peers.values())
