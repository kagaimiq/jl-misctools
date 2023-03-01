from jl_stuff import *
import argparse

ap = argparse.ArgumentParser(description='JLX cryptoz',
                             epilog='Do not abuse this!!! Only I can!')

ap.add_argument('--key', default='0xffff',
                help='Encryption key (default: %(default)s)')

ap.add_argument('--block', default='32',
                help='Block size (default: %(default)s bytes)')

ap.add_argument('input',
                help='Input file')

ap.add_argument('output',
                help='Output file')

args = ap.parse_args()

key = int(args.key, 0)
blklen = int(args.block, 0)

with open(args.output, 'wb') as outf:
    with open(args.input, 'rb') as inpf:
        addr = 0

        while True:
            blk = inpf.read(blklen)
            if blk == b'': break
            addr += outf.write(jl_crypt_enc(blk, (key ^ (addr >> 2)) & 0xffff))

