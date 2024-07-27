from jltech.cipher import jl_enc_cipher
from jltech.utils import anyint
import argparse

###############################################################################

ap = argparse.ArgumentParser(description='JieLi SFC data [en/re/de]cipherer')

ap.add_argument('input',
                help='Input file')

ap.add_argument('output',
                help='Output file')

ap.add_argument('srckey', type=anyint,
                help="Input file's key (e.g. 0xffff), anything less than zero means no decryption is done")

ap.add_argument('dstkey', type=anyint,
                help="Output file's key (e.g. your chip's chipkey), anything less than zero means no encryption is done")

ap.add_argument('start', type=anyint,
                help="Encrypted data start (i.e. start of the app_dir_head, user.app, etc)")

ap.add_argument('end', type=anyint,
                help="Encrypted data end (i.e. end of the encrypted blob), note that this is *inclusive*.")

args = ap.parse_args()

###############################################################################

with open(args.input, 'rb') as f:
    data = bytearray(f.read())

for off in range(args.start, args.end, 32):
    size = min(32, args.end - off)
    adr = (off - args.start) >> 2

    if args.srckey >= 0: jl_enc_cipher(data, off, size, args.srckey ^ adr)
    if args.dstkey >= 0: jl_enc_cipher(data, off, size, args.dstkey ^ adr)

with open(args.output, 'wb') as f:
    f.write(data)
