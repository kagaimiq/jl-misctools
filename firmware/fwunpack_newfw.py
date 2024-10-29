from jltech.crc import jl_crc16
from jltech.cipher import jl_enc_cipher, jl_sfc_cipher, cipher_bytes, cipher_copy
from jltech.chipkeybin import chipkeybin_decode
from jltech.utils import *

from pathlib import Path
import struct
import yaml
import argparse

###############################################################################

ap = argparse.ArgumentParser(description='New-Firmware unpacker')

ap.add_argument('--dirname', default='{fpath}_unpack',
                help='Output directory name template, default: "%(default)s";'
                     'where {fpath} is a path to the source file,'
                     ' {fdir} is the directory the file resides in and'
                     ' {fname} is just the source file name.')

ap.add_argument('input', type=Path, nargs='+',
                help='Input firmware files')

args = ap.parse_args()

###############################################################################

class JLFSEntry:
    def __init__(self, buff, off=0, database=0, data_after_header=False):
        # Read the entry header and check its CRC
        hcrc, hdr = struct.unpack_from('<H30s', buff, off)
        if jl_crc16(hdr) != hcrc:
            raise ValueError('JLFS entry header CRC mismatch')

        # Decode the fields
        edcrc, eoff, esize, eflags, eresvd, eindex, ename = struct.unpack('<HIIBBH16s', hdr)

        self.hdr_off  = off
        self.data_crc = edcrc
        self.offset   = eoff
        self.size     = esize
        self.flags    = eflags
        self.resvd    = eresvd
        self.index    = eindex
        self.raw_name = ename

        if data_after_header:
            # data goes immediately after the header
            self.data_offset = self.hdr_off + 32
        else:
            # relative to the data base address
            self.data_offset = self.offset + database

        if data_after_header:
            # the size field reports the size of a *whole* block of data (i.e. with the header too)
            self.data_size = self.hdr_off + self.size - self.data_offset
        else:
            # actual data size is this
            self.data_size = self.size

        self.name = nulltermstr(ename, 'ascii')

    def __str__(self):
        return f'<JLFS Entry @{self.hdr_off:08X} - {self.data_crc:04X} @{self.offset:08X}/{self.data_offset:08X} ({self.size:10}/{self.data_size:10}) - {self.flags:02X}/{self.resvd:02X} / {self.index} -- "{self.name}">'

class JLFSIterator:
    def __init__(self, buff, base, off=0, key=None, sfc=False):
        self.buff = buff
        self.baseaddr = base
        self.offset = off
        self.key = key
        self.is_sfc_area = sfc
        self.is_over = False
        self.dec_off = self.baseaddr

    def __iter__(self):
        return self

    def __next__(self):
        if self.is_over:
            raise StopIteration

        entoff = self.baseaddr + self.offset

        if self.key is not None:
            if self.is_sfc_area:
                next = align_to(entoff + 32, 32)
                if self.dec_off < next:
                    num = next - self.dec_off
                    jl_sfc_cipher(self.buff, self.dec_off, num, self.baseaddr, self.key)
                    self.dec_off += num
            else:
                jl_enc_cipher(self.buff, entoff, 32, self.key)

        # decode the entry
        entry = JLFSEntry(self.buff, entoff, self.baseaddr, self.is_sfc_area)

        # the index is a nonzero when that was the last entry
        self.is_over = entry.index != 0

        if self.is_sfc_area:
            # skip the whole entry block to a next one
            self.offset += entry.size

            if self.key is not None:
                next = self.baseaddr + self.offset

                if not self.is_over:
                    # not the last one, decrypt everything down to a next entry header
                    next = align_to(next + 32, 32)

                # decrypt all the stuff now
                if self.dec_off < next:
                    num = next - self.dec_off
                    jl_sfc_cipher(self.buff, self.dec_off, num, self.baseaddr, self.key)
                    self.dec_off += num
        else:
            # go to the next entry header
            self.offset += 32

        return entry

#---------------------------------------------------------------------------------------------

#
# yet another copy of the bankcb descrambling code
#
def descramble_bankcb(data, base, key):
    # same as usual.
    bankcount = 1
    index = 0

    while index < bankcount:
        hdroff = base + index * 16
        jl_enc_cipher(data, hdroff, 16, key)
        hdr, hcrc = struct.unpack_from('<14sH', data, hdroff)

        if jl_crc16(hdr) != hcrc:
            raise ValueError(f'Bank {index} header CRC mismatch.')

        bankid, banksize, bankload, bankoff, bankcrc = struct.unpack('<HHIIH', hdr)

        if index == 0:
            bankcount = bankid

        # decrypt the bank contents in all of its entirety.
        jl_enc_cipher(data, base + bankoff, banksize, key)

        index += 1

#---------------------------------------------------------------------------------------------

def parse_newfw(info, fw, outdir:Path):
    info['format'] = 'jl-new-fw'

    baseoff = None
    headerkey = 0xFFFF

    # Locate the flash header from a few hardcoded offsets that the Boot ROM checks for..
    for off in [0, 0x1000, 0x10000, 0x80000, 0x100000, 0x180000]:
        header = fw[off:off+32]  # a local copy in order to not destroy the original contents
        jl_enc_cipher(header, 0, len(header), headerkey)  # descramble the header

        hcrc, hdata = int.from_bytes(header[:2], 'little'), header[2:]
        if hcrc != 0 and jl_crc16(hdata) == hcrc:
            # valid and correct CRC

            # put the unscrambled header portions into the descrambled data
            # which are the VID (version) and PID (product) strings.
            header = header[:4] + fw[off+4:off+8] + header[8:16] + fw[off+16:off+32]

            # we got it!
            baseoff = off
            break

    if baseoff is None:
        raise RuntimeError("Could not locate the base offset of the firmware.")

    print(f'Firmware base is at @{baseoff:X}')
    info['base-offset'] = baseoff

    #
    # we got a flash header, let's parse it... kind of
    #
    fhcrc, fburnersz, fvid, fflashsz, ffsver, fblockalign, fresvd, fspecopt, fpid = \
        struct.unpack('<HH4sIBBBB16s', header)

    print(f'  Burner size....: {fburnersz}')
    print(f'  VID............: {fvid}')
    print(f'  Flash size.....: ${fflashsz:06X}')
    print(f'  FS version.....: {ffsver}')
    print(f'  Block alignment: {fblockalign}')
    print(f'  Special option.: ${fspecopt:02X}')
    print(f'  PID............: {fpid}')

    #------------------------------------------------------------

    chipkey = None
    appbase = None

    topdir = outdir/'top'
    topdir.mkdir()

    for i, ent in enumerate(JLFSIterator(fw, baseoff, len(header), key=headerkey)):
        print('(top)', ent)

        foutpath = topdir/ent.name

        if i == 0:
            # the Boot ROM assumes the first file entry is the SPL
            #  aka the 'uboot.boot'.

            descramble_bankcb(fw, ent.data_offset, headerkey)

            info['spl'] = dict(
                file = str(foutpath.relative_to(outdir)),
                # bit6 of flags denotes the SPL being compressed.
                compressed = bool(ent.flags & 0x40)
            )

        elif ent.flags == 0x81:
            # that's one of the app_dir_head's
            if ent.name == 'app_dir_head':
                if appbase is None:
                    # assign this as our app_dir_head
                    appbase = ent.data_offset

            continue # don't dump it to a file

        elif ent.flags & 0x10:
            # skip the reserved area definitions too
            #  e.g. the "key_mac".
            continue

        elif ent.name == 'isd_config.ini':
            # isd_config file. It's special.

            # I found out that there is a chipkey encoded there, so let's use that.
            ckdata, ckcrc = struct.unpack_from('<32sH', fw, ent.data_offset)
            if jl_crc16(ckdata) == ckcrc:
                # Here's the chipkey!
                chipkey = chipkeybin_decode(ckdata)
                print(f'Firmware chipkey from isd_config.ini: {chipkey:04X}')

            # the rest is TODO..

        # dump to a file..
        foutpath.write_bytes(fw[ent.data_offset : ent.data_offset + ent.data_size])

    #------------------------------------------------------------

    if appbase is None:
        raise RuntimeError('An app_dir_head has not been found.')

    if chipkey is None:
        # I won't bother with the bruteforce code since we can just rely
        # on the isd_config.ini file contents parsed above.
        raise RuntimeError('Unknown chipkey.')

    print(f'Using chipkey: ${chipkey:04X}')
    info['chip-key'] = chipkey

    #
    # Now, we can go through everything that is in the app area.
    #

    appfiles = []
    resfiles = []

    # logically the resource entries follow entries located in app_area_head.
    filesdir = outdir/'files'
    filesdir.mkdir()

    for i, ent in enumerate(JLFSIterator(fw, appbase, 0, key=chipkey, sfc=True)):
        if i == 0:
            print('(App Area Head)', ent)

            # offset field of the app_area_head is the entry point address.
            info['entry-point'] = ent.offset
            print(f'Entry point address: 0x{ent.offset:X}')

            for aent in JLFSIterator(fw, ent.hdr_off, ent.data_offset - ent.hdr_off):
                print('(App)', aent)

                if aent.flags & 0x10:
                    # reserved area
                    pass
                elif aent.flags != 0x82:
                    # what is that?
                    raise ValueError('Invalid flags for a regular file in the app_area_head.')
                else:
                    # a regular file.
                    fpath = filesdir / aent.name
                    fpath.write_bytes(fw[aent.data_offset : aent.data_offset + aent.data_size])
                    appfiles.append(str(fpath.relative_to(outdir)))

        else:
            print('(Res)', ent)

            fpath = filesdir / ent.name

            if ent.flags & 0x10:
                # more of reserved areas
                pass
            elif ent.flags == 0x82:
                # regular file
                fpath.write_bytes(fw[ent.data_offset : ent.data_offset + ent.data_size])
                resfiles.append(str(fpath.relative_to(outdir)))
            else:
                # something else. dump it with the header!
                fpath.write_bytes(fw[ent.hdr_off : ent.hdr_off + ent.size])
                resfiles.append(str(fpath.relative_to(outdir)))

                if ent.flags == 0x83:
                    # actually, that is a directory. so extract its contents too
                    extradir = filesdir / f'{ent.name}-extracted'
                    extradir.mkdir()

                    for aent in JLFSIterator(fw, ent.hdr_off, ent.data_offset - ent.hdr_off):
                        print('====>', aent)
                        fpath = extradir / aent.name
                        fpath.write_bytes(fw[aent.data_offset : aent.data_offset + aent.data_size])

    if len(appfiles) > 0: info['app-files'] = appfiles
    if len(resfiles) > 0: info['res-files'] = resfiles

#---------------------------------------------------------------------------------------------

def load_ufw_now(f, header, key=0xffff):
    offskew = f.tell() - len(header)

    # descramble the header data
    jl_enc_cipher(header, 0, 0x40, key=key)

    # check the header's CRC
    hdrcrc, hdata = struct.unpack_from('<H62s', header, 0)
    if jl_crc16(hdata) != hdrcrc:
        return None

    # parse header
    hdrcrc, listcrc, imgsize, numents, wa3, wa4, chipname = \
        struct.unpack_from('<HHIHHI48s', header, 0)

    headersize = 0x40 + numents * 0x50

    if len(header) < headersize:
        # load the missing header data if required.
        header += f.read(headersize - len(header))

    # check the entry list CRC.
    if jl_crc16(header[0x40 : headersize]) != listcrc:
        return None

    # if we got there it means that we have a valid ufw file.
    print('--- UFW file ---')
    print(f' chip name: "{nulltermstr(chipname, "ascii")}"')

    # parse entry data
    for off in range(0x40, headersize, 0x50):
        jl_enc_cipher(header, off, 0x50, key=key)
        etype, eindex, edcrc, ewa1, eoffset, esize, esize2, ewa2, ename = \
            struct.unpack_from('<HHHHIII44s16s', header, off)

        if etype == 0:
            # okay here we are, this is our flash.bin
            f.seek(eoffset + offskew)
            fw = f.read(esize)
            if jl_crc16(fw) != edcrc:
                print('data crc mismatch but who cares?')
            return fw

def load_ufw(f):
    header = bytearray(f.read(0x40))
    return load_ufw_now(f, header)

def load_fwsc(f):
    header = bytearray()
    for i in range(20):
        block = f.read(0x30)
        header += block[:0x2f]
    return load_ufw_now(f, header)

def load_raw(f):
    return f.read()  # that's it

def parsefw(path:Path, outdir:Path):
    # Load firmware data
    with open(path, 'rb') as f:
        for loader in [load_ufw, load_fwsc, load_raw]:
            f.seek(0)
            fw = loader(f)
            if fw is not None:
                break

    if fw is None:
        raise RuntimeError('Could not load the firmware data.')

    # make it mutable
    fw = bytearray(fw)

    # Now make an output directory
    outdir.mkdir(parents=True)

    info = {}

    try:
        # Parse the firmware

        parse_newfw(info, fw, outdir)

    finally:
        # Dump current firmware data buffer
        with open(outdir/'decrypted.bin', 'wb') as f:
            f.write(fw)

        # Dump the info file
        with open(outdir/'jlfw.yaml', 'w') as f:
            yaml.dump(info, f)

#---------------------------------------------------------------------------------------------

for path in args.input:
    print(f'#\n# {path}\n#\n')
    try:
        parsefw(path, Path(args.dirname.format(fpath=path, fname=path.name, fdir=path.parent)))
    except Exception as e:
        print('[!]',e)
    print()
