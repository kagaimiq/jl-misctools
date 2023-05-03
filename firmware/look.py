from jl_stuff import *
import argparse, struct

ap = argparse.ArgumentParser(description='Look!')

def anyint(s):
    return int(s, 0)

ap.add_argument('file', type=argparse.FileType('rb'),
                help='Input file')

ap.add_argument('--sfckey', type=anyint, default=0xffff, metavar='KEY',
                help='SFC ENC key (i.e. your chipkey) (default: 0x%(default)04x)')

args = ap.parse_args()


with args.file as f:
    enc_en = True
    enc_key = 0xFFFF

    sfc_base = 0
    sfcenc_en = True
    sfcenc_key = args.sfckey

    def flash_read(addr, length):
        f.seek(addr)
        dat = f.read(length)

        if len(dat) < length:
            dat += bytes(length - len(dat))

        return dat

    def spienc_read(addr, length):
        dat = flash_read(addr, length)

        if enc_en:
            dat = jl_crypt_enc(dat, enc_key)

        return dat

    def sfc_read(addr, length):
        rdata = b''

        while length > 0:
            paddr = addr & ~0x1F
            poffs = addr & 0x1f

            n = 0x20 - poffs
            if n > length: n = length

            pdata = flash_read(sfc_base + paddr, 0x20)

            if sfcenc_en:
                pdata = jl_crypt_enc(pdata, sfcenc_key ^ ((paddr >> 2) & 0xffff))

            rdata += pdata[poffs:poffs+n]

            addr += n
            length -= n

        return rdata

    ####### ####### ####### ####### ####### ####### ####### #######
    ##   ## #     # #     # #     # # #  ## # #   # # ### # # ### #
    # ### # ## #### ### ### ## #### #  ## # ## #### # ### # #  ## #
    #     # # #   # ### ### ### ### # ### # ### ### # ### # # # # #
    # ### # # ##### ### ### ## #### #    ## #### ## # ### # # ##  # .S3M
    # ### # # ##### ### ### #     # # ### # #   # # ##    # # ### # 4F/39
    ####### ####### ####### ####### ####### ####### ####### #######

    print("\n============================ ENC >>>>>>>============================")



    ######################
    #
    # (Flash header)
    #
    ######################
    pos = 0x00

    ent = spienc_read(pos, 0x20)
    entc = jl_crypt_enc(ent)
    pos += 0x20

    xent = ent[:4] + entc[4:8] + ent[8:16] + entc[16:]

    hexdump(ent)

    hcrc, bsize, vid, fsize, fver, balign, rsv, sopt, pid = struct.unpack('<HH4sIBBBB16s', xent)

    print('<%04x> %5d [%s] %d %x %d %02x %02x [%s]' % (hcrc, bsize, vid, fsize, fver, balign << 8, rsv, sopt, pid))

    ######################
    #
    # (Top-level files)
    #
    ######################
    while True:
        ent = spienc_read(pos, 0x20)
        pos += 0x20

        hexdump(ent)

        hcrc, dcrc, off, size, attr, rsv, idx, name = struct.unpack('HHIIBBH16s', ent)

        print('<%04x> %04x | @%08x (%08x) | %02x/%02x (%5d) | %s' % (hcrc, dcrc, off, size, attr, rsv, idx, name))

        if attr == 0x81:
            sfc_base = off

        if idx != 0: break

    print("\n============================ SFC >>>>>>>============================")

    ######################
    #
    # (Main files)
    #
    ######################
    pos = 0x00

    while True:
        ent = sfc_read(pos, 0x20)
        pos += 0x20

        hexdump(ent)

        hcrc, dcrc, off, size, attr, rsv, idx, name = struct.unpack('HHIIBBH16s', ent)

        print('<%04x> %04x | @%08x (%08x) | %02x/%02x (%5d) | %s' % (hcrc, dcrc, off, size, attr, rsv, idx, name))

        if idx != 0: break
