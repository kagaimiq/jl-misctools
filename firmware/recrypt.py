from jl_stuff import *
import argparse

ap = argparse.ArgumentParser(description='JieLi SFC data recryptor')

def anyint(s):
    return int(s, 0)

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
                help="Encrypted data end (i.e. end of the encrypted blob)")

args = ap.parse_args()

with open(args.input, 'rb') as f:
    data = bytearray(f.read())

for pos in range(args.start, args.end, 32):
    mxlen = min(32, args.end - pos)
    chunk = data[pos:pos+mxlen]

    abspos = (pos - args.start)

    if not (args.srckey < 0):
        chunk = jl_crypt_enc(chunk, (args.srckey ^ (abspos >> 2)) & 0xffff)

    if not (args.dstkey < 0):
        chunk = jl_crypt_enc(chunk, (args.dstkey ^ (abspos >> 2)) & 0xffff)

    data[pos:pos+mxlen] = chunk

with open(args.output, 'wb') as f:
    f.write(data)
