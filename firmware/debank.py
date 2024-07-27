from jltech.cipher import jl_enc_cipher, cipher_bytes
from jltech.crc import jl_crc16
import struct, argparse
from pathlib import Path

############################################################

def anyint(s):
    return int(s, 0)

ap = argparse.ArgumentParser('Extract banks from a BANKCB image')

ap.add_argument('--key', type=anyint,
                help='Decrypt the bank contents with a specified key (e.g. 0xFFFF)')

ap.add_argument('--offset', type=anyint, default=0,
                help='Offset in the file where the required BANKCB image is located (defaults to the file beginning)')

ap.add_argument('--bigendian', action='store_true',
                help='Treat the multi-byte fields in big-endian instead of little endian')

ap.add_argument('file', type=Path,
                help='Input file')

args = ap.parse_args()

############################################################

with open(args.file, 'rb') as f:
    bcoffset = args.offset
    key = args.key

    def read(off, size):
        f.seek(bcoffset + off)
        data = f.read(size)
        if key is not None:
            data = cipher_bytes(jl_enc_cipher, data, key=key)
        return data

    ######################################

    endian = '>' if args.bigendian else '<'

    if key is not None:
        oldkey = key
        didit = False

        for i in range(0x10000):
            key = oldkey ^ i

            bhdr, bhcrc = struct.unpack(endian + '14sH', read(0, 16))

            if jl_crc16(bhdr) != bhcrc:
                continue

            bidx, bsize, bload, boff, bcrc = struct.unpack(endian + 'HHIIH', bhdr)

            data = read(boff, bsize)
            if jl_crc16(data) == bcrc:
                didit = True
                break

        if didit:
            if key != oldkey:
                print('The real key is: %04x' % key)
            else:
                print('The key seems to be correct')
        else:
            print("Wasn't able to pick a key")
            key = oldkey

    ############################################################################################

    outdir : Path = args.file.parent / (args.file.name + '_banks_%x' % bcoffset)
    outdir.mkdir(exist_ok=True)

    bankidx = 0
    bankcnt = 0

    while bankidx <= bankcnt:
        bhdr, bhcrc = struct.unpack(endian + '14sH', read(bankidx * 16, 16))
        if jl_crc16(bhdr) != bhcrc:
            if bankidx == bankcnt:
                break # ignore for the last bank - may be an inclusive bank count
            raise ValueError('Invalid bank %d header CRC' % bankidx)

        bidx, bsize, bload, boff, bcrc = struct.unpack(endian + 'HHIIH', bhdr)
        print('%2d: @%-8x -> @%-8x (%-5d) | %04x' % (bidx, boff, bload, bsize, bcrc))

        # the first bank entry defines the total bank count
        if bankidx == 0:
            bankcnt = bidx

        data = read(boff, bsize)
        if jl_crc16(data) != bcrc:
            raise ValueError('Bank %d data CRC mismatch' % bankidx)

        (outdir / ('bank_%d_%x.bin' % (bidx, bload))).write_bytes(data)

        bankidx += 1

