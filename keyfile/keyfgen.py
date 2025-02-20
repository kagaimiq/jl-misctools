import argparse
import crcmod
from Cryptodome.Cipher import AES

jl_crc16 = crcmod.mkCrcFun(0x11021,     initCrc=0x0000,     rev=False)
jl_crc32 = crcmod.mkCrcFun(0x104C11DB7, initCrc=0x26536734, rev=True)

################################################################################

def hexint(s):
    return int(s, 16)

ap = argparse.ArgumentParser(description='JieLi keyfile generator')

ap.add_argument('-o', '--out', metavar='FILE',
                help='Output file (if omitted no file will be generated)')

ap.add_argument('key', type=hexint,
                help='Chipkey to encode (a 16-bit hexadecimal number)')

args = ap.parse_args()

################################################################################

# generate the data payload
data = f'{args.key:04X}A000\0'.encode()
data += b'\xff' * (16 - len(data))

# encrypt that with AES
key = AES.get_random_bytes(8) * 2
data = AES.new(key, AES.MODE_ECB).encrypt(data) + key

# append a CRC32 checksum
data = data.hex()
data += f'{jl_crc32(data.encode()):08x}'

# ... and that's it.
keyfile = data.encode()

crcstring = f'{jl_crc16(keyfile):04X}-{jl_crc32(keyfile):08X}'

print('CRC:', crcstring)
print(f'keyfile: [{keyfile.decode()}]')

if args.out is not None:
    with open(args.out, 'wb') as f:
        f.write(keyfile)
