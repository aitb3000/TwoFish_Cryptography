import base64
from hashlib import blake2b
from hmac import compare_digest

AUTH_SIZE = 16


def sign(msg, key):
    key = base64.b64encode((str(key)).encode("utf-8"))
    h = blake2b(digest_size=AUTH_SIZE, key=key)
    h.update(str(msg).encode('utf-8'))
    return h.hexdigest().encode('utf-8')


def verify(msg, key, sig):
    good_sig = sign(msg, key)
    return compare_digest(good_sig, sig)
