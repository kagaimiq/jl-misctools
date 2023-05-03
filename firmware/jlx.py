from jl_stuff import *
import argparse

ap = argparse.ArgumentParser(description='JLX cryptoz for specifiles of XYZ',
                             epilog='Do not use this to encrypt your specifiles. Only I am allowed to do that!')

def anyint(s):
    return int(s, 0)

ap.add_argument('--key', default=0xffff, type=anyint,
                help='Encryption key (default: 0x%(default)x)')

ap.add_argument('--block', default=32, type=anyint,
                help='Block size (default: %(default)d bytes)')

ap.add_argument('input',
                help='Input file')

ap.add_argument('output',
                help='Output file')

args = ap.parse_args()

with open(args.output, 'wb') as outf:
    with open(args.input, 'rb') as inpf:
        addr = 0

        while True:
            blk = inpf.read(args.block)
            if blk == b'': break
            addr += outf.write(jl_crypt_enc(blk, (args.key ^ (addr >> 2)) & 0xffff))

