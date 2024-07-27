"""
chipkey.bin file format
"""

__all__ = [
    'chipkeybin_decode',
    'chipkeybin_encode',
]

from jltech.crc import jl_crc16
from random import randint


def chipkeybin_decode(data):
    """ Decode the actual contents of the chipkey.bin file (32 bytes long) """

    if len(data) < 32:
        raise RuntimeError('The provided data buffer should be at least 32 bytes long!')

    thesum = sum(data[:16]) & 0xFF
    if thesum >= 0xE0:
        thesum = 0xAA
    elif thesum <= 0x10:
        thesum = 0x55

    key = 0

    for i in range(16):
        if (data[16 + i] ^ data[15 - i]) < thesum:
            key |= (1 << i)

    return key

def chipkeybin_encode(key):
    """ Encode the key into the 32-byte blob stored in chipkey.bin """

    # generate some random entropy
    data = [randint(0,255) for i in range(16)]

    thesum = sum(data) & 0xFF
    if thesum >= 0xE0:
        thesum = 0xAA
    elif thesum <= 0x10:
        thesum = 0x55

    # encode the chipkey bits!
    for i in range(16):
        if key & (1<<i):
            # anything below "thesum"
            val = randint(0, thesum-1)
        else:
            # equal to or above "thesum"
            val = randint(thesum, 255)
        data.append(val ^ data[15 - i])

    return bytes(data)
