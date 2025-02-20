import argparse
import crcmod
from Cryptodome.Cipher import AES

jl_crc16 = crcmod.mkCrcFun(0x11021,     initCrc=0x0000,     rev=False)
jl_crc32 = crcmod.mkCrcFun(0x104C11DB7, initCrc=0x26536734, rev=True)

################################################################################

ap = argparse.ArgumentParser(description='JieLi keyfile parser')

ap.add_argument('keyfile', nargs='+',
                help='Key file(s) to parse')

args = ap.parse_args()

################################################################################

def parse_keyfile(fpath):
    with open(fpath, 'rb') as f:
        keyfile = f.read(72)

    print(f'CRC: <{jl_crc16(keyfile):04X}-{jl_crc32(keyfile):08X}>')
    print(f'file: {keyfile.decode()}')

    # extract the data string and the CRC
    data = keyfile[:64]
    crc_val = int(keyfile[64:72], 16)

    # check the CRC of the data string and the in-file CRC
    crc_data = jl_crc32(data)

    if crc_data != crc_val:
        raise ValueError('Key file CRC mismatch')

    # get the byte string from the hex string
    data = bytes.fromhex(data.decode())

    # decrypt with AES (in ECB mode) with the first half being ciphertext
    #  and the second one being the decryption key
    data = AES.new(data[16:], AES.MODE_ECB).decrypt(data[:16])

    print(f'data: {data}')

    val1 = int(data[0:4], 16)
    val2 = int(data[4:8], 16)

    print(f'val1={val1:04X}, val2={val2:04X}')

    if val2 == 0xa000:
        # this is the chip key.
        return val1
    else:
        raise ValueError(f'Unknown second hex value "{val2:04X}"')

for keyfile in args.keyfile:
    print("##############[ %s ]##############" % keyfile)

    try:
        key = parse_keyfile(keyfile)
        if key is None:
            print('** failed **')
        else:
            print(f'Chip key: >>> 0x{key:04X} <<<')
    except Exception as e:
        print("{!} Exception while parsing key:", e)

    print()
