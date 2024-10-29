from jltech.cipher import jl_enc_cipher, cipher_bytes
from jltech.crc import jl_crc16
from jltech.utils import *

from pathlib import Path
import argparse
import struct

###############################################################################

ap = argparse.ArgumentParser(description='DVxx unpacker')

ap.add_argument('--offset', type=anyint, default=0,
                help='Offset of the main syd within the file (note: affects *all* files)')

ap.add_argument('--hdrkey', type=anyint, default=0xFFFF,
                help='Header key (default: 0x%(default)04x)')

ap.add_argument('--dirname', default='{fpath}_unpack',
                help='Unpack directory name template, default: "%(default)s".'
                     ' ({fpath} refers to the full file path, {fdir} refers to the directory name the file resides in, {fname} refers to the file name)')

ap.add_argument('input', type=Path, nargs='+',
                help='Firmware file(s) to unpack')

args = ap.parse_args()

###############################################################################

def bankcb_decipher(buff, key=0xFFFF):
    totalsize = 0
    hdroff = 0
    numbanks = 1
    idx = 0

    while idx < numbanks:
        jl_enc_cipher(buff, hdroff, 16, key)

        hdr, hcrc = struct.unpack_from('<14sH', buff, hdroff)
        if jl_crc16(hdr) != hcrc:
            raise RuntimeError('BankCB header CRC mismatch')

        bankid, size, load, offset, crc = struct.unpack('<HHIIH', hdr)
        totalsize = max(totalsize, offset + size)

        if idx == 0:
            numbanks = bankid

        jl_enc_cipher(buff, offset, size, key)

        if jl_crc16(buff[offset : offset+size]) != crc:
            print(f'bank {idx}/{bankid} CRC mismatch')

        hdroff += 16
        idx += 1

    return totalsize, numbanks

def apu_decipher(buff, key=0xFFFF):
    dkey = jl_enc_cipher(buff, 0, 16, key)

    if buff[2] == 0xA5:  # that's probably how you can tell these formats apart
        # AC520N uboot V3.00 format
        jl_enc_cipher(buff, 16, 4, dkey)  # decipher the remaining 4 bytes
        dataoff = 20
        # not sure if the header field at 12-15 is the cipher block size (It was set to 0x8000 in my case)
        blksize = 0x8000
    else:
        # usual APU format
        dataoff = 16
        blksize = 0x8000

    # decipher the data
    for off in range(dataoff, len(buff), blksize):
        jl_enc_cipher(buff, off, min(blksize, len(buff) - off), key)

###############################################################################

def syd_dump(file, offset, outdir:Path, hkey=None):
    outdir.mkdir(exist_ok=True, parents=True)

    #
    # Read the header
    #

    file.seek(offset)

    # Read and decipher the header blob
    header = bytearray(file.read(32))
    if hkey is not None:
        jl_enc_cipher(header, 0, len(header), hkey)

    # Check its CRC
    hcrc, hdr = struct.unpack('<H30s', header)
    if jl_crc16(hdr) != hcrc:
        raise RuntimeError('SYD header CRC mismatch')

    # extract some fields off of it
    lcrc, info1, info2, fcount, ver1, ver2, chiptype = struct.unpack('<HIIIII8s', hdr)

    # Read the file entries and check their CRC
    header += file.read(fcount * 32)
    if lcrc != 0 and jl_crc16(header[32:]) != lcrc:
        raise RuntimeError('File list CRC mismatch')

    # Decipher the file list
    if hkey is not None:
        for off in range(32, len(header), 32):
            jl_enc_cipher(header, off, 32, hkey)

    # Dump the header contents
    (outdir/'__header__').write_bytes(header)

    #
    # Dump the contents
    #

    for off in range(32, len(header), 32):
        ftype, fresvd, fcrc, foffset, fsize, findex, fname = struct.unpack_from('<BBHIII16s', header, off)
        fname = nulltermstr(fname, encoding='gb2312')

        print(f'-- {ftype:02X}/{fresvd:02X} - {fcrc:04X} - @{foffset:06X} ({fsize}) "{fname}"')

        outpath = outdir/fname
        dataoffset = offset + foffset

        if ftype == 0 and fname.endswith('.res') and fname not in ('menu.res'):
            # Might be the nested sydfs structure..
            #  TODO better filters for the unrelated files e.g. menu.res
            try:
                syd_dump(file, dataoffset, outpath, hkey)
                continue
            except Exception as e:
                print('  [*] failed to parse the nested sydfs:', e)
                # in case it already made a directory
                if outpath.exists():
                    outpath.rmdir()

        # dump this file
        file.seek(dataoffset)
        data = bytearray(file.read(fsize))

        if ftype == 1:
            # uboot.boot bankcb file
            bankcb_decipher(data, key=hkey)
        elif ftype == 4:
            # sdram.apu compressed app file
            apu_decipher(data, key=hkey)

        if jl_crc16(data) != fcrc:
            print('   [*] file CRC mismatch!')

        outpath.write_bytes(data)

def parse_fw(file, outdir):
    syd_dump(file, args.offset, outdir, hkey=args.hdrkey)

###############################################################################

for fpath in args.input:
    print(f'#\n# {fpath}\n#\n')

    try:
        with open(fpath, 'rb') as f:
            parse_fw(f,
                Path(args.dirname.format(fpath=fpath, fname=fpath.name, fdir=fpath.parent))
            )
    except Exception as e:
        print('[!]', e)

    print()
