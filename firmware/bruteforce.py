from jltech.cipher import jl_enc_cipher, cipher_bytes
import argparse

################################################################################

ap = argparse.ArgumentParser(description='JieLi chipkey (SFCENC key) bruteforce',
                             epilog='We still can guess it no matter what!!')

ap.add_argument('reference',
                help='Reference file (e.g. sdram.app, sdk.app, app.bin, etc)')

ap.add_argument('file',
                help='File to bruteforce on (i.e. a flash dump, bfu file, etc)')

ap.add_argument('offset',
                help='Input file offset (i.e. tart of the encrypted area)')

args = ap.parse_args()

################################################################################

with open(args.file, 'rb') as f:
    f.seek(int(args.offset, 0))
    src = f.read(32)

with open(args.reference, 'rb') as f:
    ref = f.read(32)


mmatched = 0
kmatched = 0

matcheds = {}

for i in range(0x100):
    key = ((src[0] ^ ref[0]) * 0x0101) ^ (i << 8)

    dec = cipher_bytes(jl_enc_cipher, src, key=key)

    nmatched = 0

    for i, b in enumerate(dec):
        if b == ref[i]: nmatched += 1

    if mmatched < nmatched:
        mmatched = nmatched
        kmatched = key

    if not nmatched in matcheds:
        matcheds[nmatched] = []

    matcheds[nmatched].append(key)

for count in sorted(matcheds)[-5:]:
    print('%3d:' % count, ' '.join(['%04X' % i for i in matcheds[count]]))

print("Possibly it's >>>> %04X <<<<" % kmatched)
