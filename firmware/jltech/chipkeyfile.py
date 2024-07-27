
__all__ = [
    'keyfile_decode',
    'keyfile_encode',
    'keyfile_parse',
    'keyfile_create'
]

from jltech.crc import jl_crc32
from jltech.utils import align_by
from Cryptodome.Cipher import AES

def keyfile_decode(data):
    """ Decode a key file into raw contents """

    # sanity check the size
    if len(data) < 72:
        raise RuntimeError('The size of a key file shall be no less than 72 characters')

    # check the CRC
    fcrc = int(data[64:72], 16)
    ccrc = jl_crc32(data[:64].encode())
    if fcrc != ccrc:
        raise ValueError(f'Key file contents CRC mismatch ({fcrc:08X} != {ccrc:08X})')

    # extract the data
    data = bytes.fromhex(data[:64])

    # decrypt the data
    data = AES.new(data[16:], AES.MODE_ECB).decrypt(data[:16])

    # here are your data
    return data

def keyfile_encode(data, key=None):
    """ Encode raw data into a key file """

    # generate the key, if neccessary
    if key is not None:
        if len(key) != 16:
            raise ValueError('The key length shall be 16 bytes long')
    else:
        key = AES.get_random_bytes(8) * 2

    # pad the data with 0xFF's if it is less than 16 bytes long
    if len(data) < 16:
        data += b'\xff' * align_by(len(data), 16)

    # encrypt the data and append the key
    data = AES.new(key, AES.MODE_ECB).encrypt(data[:16]) + key

    # make the key file
    data = data.hex()
    data += f'{jl_crc32(data.encode()):08x}'

    # here's your key file contents
    return data

def keyfile_parse(data):
    """ Parse the key file and return the chipkey it carries """
    data = keyfile_decode(data)

    # extract hex values
    val1 = int(data[0:4], 16)
    val2 = int(data[4:8], 16)

    if val2 == 0xa000:
        # plain chipkey
        return val1
    else:
        raise ValueError(f'Invalid value of val2 ({val2:04X}), meaning of val1 ({val1:04X}) is currently unknown')

def keyfile_create(key):
    """ Create a key file from a chipkey value """
    return keyfile_encode(f'{key:04x}a000\0'.encode())
