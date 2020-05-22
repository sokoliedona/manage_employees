import os
from binascii import hexlify


def generate():
    return hexlify(os.urandom(32)).decode()
