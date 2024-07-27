from jltech.crc import jl_crc16
from jltech.cipher import jl_enc_cipher, cipher_bytes
from jltech.chipkeybin import chipkeybin_decode
from jltech.utils import hexdump, nulltermstr

from pathlib import Path

import argparse
import struct
import yaml

###################################################################################################

ap = argparse.ArgumentParser(description='BR17 firmware unpacker')

ap.add_argument('--format', default='{fpath}_unpack',
                help='Unpack directory name template, default: "%(default)s".'
                     ' ({fpath} refers to the full file path, {fdir} refers to the directory name the file resides in, {fname} refers to the file name)')

ap.add_argument('file', type=Path, nargs='+',
                help='Input firmware file(s)')

args = ap.parse_args()

###################################################################################################

class SYDFile:
    def __init__(self, sydfs, _type, _crc16, _offset, _size, _number, _name:str):
        self.sydfs = sydfs

        self.type   = _type
        self.crc16  = _crc16
        self.offset = _offset
        self.size   = _size
        self.number = _number
        self.name   = _name

        self.absoffset = self.offset + sydfs.flash_base

    def read(self, addr, size):
        if addr > self.size:
            raise ValueError('Address out of range')

        remsize = min(size, self.size - addr)
        return self.sydfs.flash.read(self.absoffset + addr, remsize)

    def __repr__(self):
        return '<[%-16s]: %8d bytes @ %08x - CRC 0x%04x, type %d, #%d>' % \
                (self.name, self.size, self.offset, self.crc16, self.type, self.number)


class SYDReader:
    def __init__(self, flash, flashbase=0, headerbase=0, encrypted=True, size=None, headerless=False):
        self.flash = flash
        self.flash_base = flashbase
        self.header_base = flashbase + headerbase
        self.encrypted = encrypted
    
        #-----------------------------------------------------------------------------------#

        if headerless:
            if size is None:
                raise TypeError('The size should be specified for a headerless syd.')

            self.list_base = self.header_base

            self.filelist = []

            for off in range(0, size, 32):
                entry = flash.read(self.list_base + off, 32)

                # TODO, proper sanity check
                if entry[1] != 0x00:
                    break

                self.filelist.append(entry)

            self.file_count = len(self.filelist)

        else:
            fhead = flash.read(self.header_base, 32)
            if encrypted: fhead = cipher_bytes(jl_enc_cipher, fhead)
            fhcrc, fhead = struct.unpack('<H30s', fhead)

            self.list_base = self.header_base + 32

            if jl_crc16(fhead) != fhcrc:
                raise Exception('Flash header CRC mismatch')

            flcrc, finfo1, finfo2, fnum, fver, fver1, fctype = struct.unpack('<HIIIII8s', fhead)

            print('<SYD> list crc: %04x, Info: %08x %08x, count: %d, version: %08x %08x, chiptype: %s' % \
                  (flcrc, finfo1, finfo2, fnum, fver, fver1, fctype))

            if fnum > 1024:
                raise Exception('Too ambigous file count')

            self.file_count = fnum

            self.h_info     = (finfo1, finfo2)
            self.h_version  = (fver, fver1)
            self.h_chiptype = fctype

            flist = flash.read(self.list_base, self.file_count * 32)

            if jl_crc16(flist) != flcrc:
                raise Exception('File list CRC mismatch')

            self.filelist = []
            for i in range(self.file_count):
                entry = flist[i * 32 : i * 32 + 32]
                if encrypted: entry = cipher_bytes(jl_enc_cipher, entry)
                self.filelist.append(entry)

    #-------------------------------------------------#

    def get_file_by_id(self, fid):
        if fid < 0 or fid >= self.file_count:
            raise IndexError('File ID out of bounds')

        #entry = self.flash.read(self.list_base + 32 * fid, 32)
        #if self.encrypted: entry = jl_crypt_enc(entry)

        etype, eres, ecrc16, eoff, elen, enum, ename = struct.unpack('<BBHIII16s', self.filelist[fid])

        # GB2312  because they're chinese, and most importantly they're using windows so UTF-8 is not an option at all.
        ename = nulltermstr(ename, encoding='gb2312')

        return SYDFile(self,
            _type     = etype,
            _crc16    = ecrc16,
            _offset   = eoff,
            _size     = elen,
            _number   = enum,
            _name     = ename
        )

####################################################################

class FlashFile:
    def __init__(self, file, offset=0, size=None):
        self.file = file
        self.offset = offset

        if size is not None:
            self.size = size
        else:
            oldpos = file.tell()
            self.size = file.seek(0, 2) - self.offset
            file.seek(oldpos)

    def read(self, addr, size):
        #if addr >= self.size:
        #    raise ValueError('Addressing way out of bounds')
        #elif (addr + size) >= self.size:
        #    raise ValueError('Reading way out of bounds')

        #print("\x1b[1;33m  ;; flash read - %08x %d ;;\x1b[0m" % (addr, size))
        self.file.seek(self.offset + addr)
        return self.file.read(size)

class SFCMap:
    def __init__(self, flash, base, key):
        self.flash = flash
        self.base = base
        self.key = key

        if base > flash.size:
            raise ValueError('Base address goes beyond the flash size')

        self.size = flash.size - base

    def read(self, addr, size):
        baddr = addr & ~0x1F
        bsize = addr + size - baddr

        data = bytearray(self.flash.read(self.base + baddr, bsize))

        for off in range(0, bsize, 32):
            jl_enc_cipher(data, off, min(32, bsize - off), self.key ^ ((baddr + off) >> 2))

        return bytes(data[addr-baddr:])

###################################################################################################

def chipkeyfile_decode(ent):
    print('---- Chip key file ----')

    ckfile = ent.read(0, ent.size)

    print('(as specified by the file entry)')
    hexdump(ckfile)

    if jl_crc16(ckfile) != ent.crc16:
        raise Exception('Chipkey file CRC mismatch (from file entry!)')

    # there are some extra data that goes after this file entry (32 bytes)
    ckfile = ent.sydfs.flash.read(ent.absoffset, 64)

    print('(extra data)')
    hexdump(ckfile)

    ckdata, ckcrc = struct.unpack_from('<32sH', ckfile, 0)

    if jl_crc16(ckdata) != ckcrc:
        raise Exception('Chipkey file CRC mismatch (from extra data!)')

    # imperishable night
    key = chipkeybin_decode(ckdata)

    print('>>>>> CHIP KEY %04x <<<<<' % key)

    print('------------------------')

    return key



def bankcb_decrypt(data, key=0xffff):
    data = bytearray(data)

    def derange(off, len):
        de = cipher_bytes(jl_enc_cipher, data[off:off+len], key=key)
        data[off:off+len] = de
        return de

    base = 0

    while base < len(data):
        print('=== bankcb @ %x' % base)

        i = 0
        banks = 1
        maxend = 0

        while i < banks:
            bhdr, bhcrc = struct.unpack('<14sH', derange(base + i*16, 16))
            if jl_crc16(bhdr) != bhcrc:
                raise Exception('CRC mismatch for a bank %d header at %x' % (i, base))

            bnum, bsize, bload, boff, bcrc = struct.unpack('<HHIIH', bhdr)
            print('  #%d (%d) @=>%x @%x - %04x / %04x' % (bnum, bsize, bload, boff, bcrc, bhcrc))

            maxend = max(maxend, boff + bsize)

            if i == 0: banks = bnum

            bdata = derange(base + boff, bsize)
            if jl_crc16(bdata) != bcrc:
                raise Exception('CRC mismatch for a bank %d data to be loaded at %x, at %x' % (i, bload, base))

            i += 1

        base += maxend

    return bytes(data)

###################################################################################################

def parsefw(fwfile, outdir:Path):
    flash = FlashFile(fwfile)

    #====================================================================#

    f_uboot = None
    f_userapp = None
    f_syscfg = None
    f_spcaer = None
    f_chipkey = None
    f_verbin = None

    fw_pdc = None
    fw_pdn = None

    #
    # extract the pdc/pdn strings from the firmware's beginning
    #
    for i in range(0, 0x1000, 0x10):
        block = flash.read(i, 16)

        if fw_pdc is None:
            if block.startswith(b'pdc:'):
                fw_pdc = block[4:]
                print('--- PDC-> [%s]' % fw_pdc)

        elif fw_pdn is None:
            if block.startswith(b'pdn:'):
                fw_pdn = nulltermstr(block[4:], encoding='ascii')
                print('--- PDN-> [%s]' % fw_pdn)

        else:
            break

    # naive sanity check
    if fw_pdc is None or fw_pdn is None:
        raise Exception('Missing pdc:/pdn: strings!')

    #
    # scan the syd for the important firmware parts
    #
    fwsyd = SYDReader(flash)

    for n in range(fwsyd.file_count):
        ent = fwsyd.get_file_by_id(n)

        print(ent)

        if ent.name == 'uboot.boot':
            f_uboot = ent

        #elif ent.name == 'user.app':
        #    f_userapp = ent

        elif ent.name == '_____.____2':
            info2syd = SYDReader(flash, headerbase=ent.absoffset, encrypted=False, size=ent.size, headerless=True)

            for m in range(info2syd.file_count):
                ent = info2syd.get_file_by_id(m)

                if ent.name == 'ver.bin':
                    f_verbin = ent

                elif ent.name == 'user.app':
                    f_userapp = ent

                elif ent.name == 'sys.cfg':
                    f_syscfg = ent

                elif ent.name == 'spc.aer':
                    f_spcaer = ent

                elif ent.name == 'chip_key.bin':
                    f_chipkey = ent

    #====================================================================#

    print('uboot.boot file:  ', f_uboot)
    print('user.app file:    ', f_userapp)
    print('sys.cfg file:     ', f_syscfg)
    print('spc.aer file:     ', f_spcaer)
    print('chipkey.bin file: ', f_chipkey)
    print('ver.bin file:     ', f_verbin)

    #
    # kind of a sanity check
    #
    if f_uboot is None:     # second-stage bootloader should always exist
        raise Exception('Missing uboot.boot!')

    if f_userapp is None:   # this is the main application
        raise Exception('Missing user.app!')

    if f_syscfg is None:    # there is, among other things, the offset of the syd header within user.app
        raise Exception('Missing sys.cfg!')

    if f_spcaer is None:
        raise Exception('Missing spc.aer!')

    if f_chipkey is None:
        raise Exception('Missing chipkey.bin!')

    #====================================================================#

    outdir.mkdir(exist_ok=True)

    yamlpath = outdir/'jlfirmware.yaml'

    fwinfo = {
        'pdc': fw_pdc.hex(),
        'pdn': fw_pdn
    }

    fwyaml = {
        'type': 'jl-firmware',
        'variant': 'br17',
        'info': fwinfo
    }

    #====================================================================#

    ubootfile = outdir/f_uboot.name
    ubootfile.write_bytes(bankcb_decrypt(f_uboot.read(0, f_uboot.size)))
    fwinfo['uboot_boot'] = str(ubootfile.relative_to(yamlpath.parent))

    #====================================================================#

    if f_verbin is not None and f_verbin.size > 0:
        verfile = outdir/f_verbin.name
        verfile.write_bytes(f_verbin.read(0, f_verbin.size))
        fwinfo['version_info'] = str(verfile.relative_to(yamlpath.parent))

    #====================================================================#

    #
    # parse user.app!
    #
    try:
        chipkey = chipkeyfile_decode(f_chipkey)

        print('Using chipkey: %04x' % chipkey)
        fwinfo['chipkey'] = chipkey

        # SFC is mapped at the beginning of user.app
        sfc = SFCMap(flash, f_userapp.absoffset, chipkey)

        #(outdir/'user.app').write_bytes(sfc.read(0, f_userapp.size))

        # grab the sys.cfg via SFC as it is encrypted alongside with user.app!
        syscfg = sfc.read(f_syscfg.offset - f_userapp.offset, f_syscfg.size)

        if jl_crc16(syscfg) != f_syscfg.crc16:
            print('Syscfg CRC mismatch')
            return

        print('######### sys.cfg:')
        hexdump(syscfg)

        '''
        sys.cfg layout:
        [0-9]: flash config
            [ 0]: flash_id
            [ 1]: flash_size
            [ 2]: flash_file_size
            [ 3]: sdfile_head_addr
            [ 4]: spi_run_mode
                        [1:0]: SPI_DATA_WIDTH: 0=1-wire SPI, 1=2-wire SPI, 2=DSPI, 3=QSPI
                        [ 2 ]: SPI_IS_CONTINUE_READ
                        [ 3 ]: SPI_IS_OUTPUT
                        [ 4 ]: SPI_NWIRE_SEND_CMD
                        [8:5]: SPI_CS_DESELECT
            [ 5]: spi_div
            [ 6]: flash_base
            [ 7]: protected_rag
            [ 8]: cfg_zone_addr
            [ 9]: cfg_zone_size
        [10-14]: clock config
            [10]: pll_sel
            [11]: osc_freq
            [12]: osc_src
            [13]: osc_hc_en
            [14]: osc_1pin_en
        [15-16]: .. something
            [15]: address
            [16]: size
        '''

        # Flash config
        flashcfg = struct.unpack_from('<IIIIIIIIII', syscfg, 0)
        print('flash_id         = 0x%x' % flashcfg[0])
        print('flash_size       = %d'   % flashcfg[1])
        print('flash_file_size  = %d'   % flashcfg[2])
        print('sdfile_head_addr = 0x%x' % flashcfg[3])
        print('spi_run_mode     = 0x%x' % flashcfg[4])
        print('spi_div          = %d'   % flashcfg[5])
        print('flash_base       = 0x%x' % flashcfg[6])
        print('protected_arg    = 0x%x' % flashcfg[7])
        print('cfg_zone_addr    = 0x%x' % flashcfg[8])
        print('cfg_zone_size    = %d'   % flashcfg[9])
        print()

        # Clock config
        clkcfg = struct.unpack_from('<IIIII', syscfg, 10*4)
        print('pll_sel          = %d'   % clkcfg[0])
        print('osc_freq         = %d'   % clkcfg[1])
        print('osc_src          = %d'   % clkcfg[2])
        print('osc_hc_en        = %d'   % clkcfg[3])
        print('osc_1pin_en      = %d'   % clkcfg[4])
        print()

        # Whatever
        watcfg = struct.unpack_from('<II', syscfg, 15*4)
        print('rem stuff start  = 0x%x' % watcfg[0])
        print('rem stuff length = 0x%x' % watcfg[1])
        print(' ---> %08x' % (watcfg[0] + watcfg[1]))
        print()

        fwinfo['system_config'] = dict(
            flash_cfg = dict(
                flash_id         = flashcfg[0],
                flash_size       = flashcfg[1],
                flash_file_size  = flashcfg[2],
                sdfile_head_addr = flashcfg[3],
                #spi_run_mode = dict(
                #    spi_data_width       = (flashcfg[4] >> 0) & 3,
                #    spi_is_continue_read = (flashcfg[4] >> 2) & 1,
                #    spi_is_output        = (flashcfg[4] >> 3) & 1,
                #    spi_nwire_send_cmd   = (flashcfg[4] >> 4) & 1,
                #    spi_cs_deselect      = (flashcfg[4] >> 5) & 0xf,
                #    __remainder__ = flashcfg[4] >> 9
                #),
                spi_run_mode  = flashcfg[4],
                spi_div       = flashcfg[5],
                flash_base    = flashcfg[6],
                protected_arg = flashcfg[7],
                cfg_zone_addr = flashcfg[8],
                cfg_zone_size = flashcfg[9],
            ),
            clock_cfg = dict(
                pll_sel     = clkcfg[0],
                osc_freq    = clkcfg[1],
                osc_src     = clkcfg[2],
                osc_hc_en   = clkcfg[3],
                osc_1pin_en = clkcfg[4], 
            ),
            what_cfg = dict(
                start  = watcfg[0],
                length = watcfg[1],
            )
        )

        print('cfg zone:')
        hexdump(flash.read(flashcfg[8] + flashcfg[6], flashcfg[9]))

        print('######### user.app:')

        #
        # finally extract data from the user.app, whose syd header starts with offset specified in sys.cfg
        #

        appsyd = SYDReader(sfc, headerbase=flashcfg[3], encrypted=False)

        appdatadir = outdir/'app-data'
        appdatadir.mkdir(exist_ok=True)

        fwinfo['app_files'] = []

        for mm in range(appsyd.file_count):
            ent = appsyd.get_file_by_id(mm)

            print(ent)
            hexdump(ent.read(0, 0x40))

            data = ent.read(0, ent.size)
            if jl_crc16(data) != ent.crc16:
                print('Warning: CRC16 does not match!')

            outfile = appdatadir/ent.name
            outfile.write_bytes(data)

            fwinfo['app_files'].append(str(outfile.relative_to(yamlpath.parent)))

    except Exception as e:
        print('<!> Failed to parse user app:', e)

    #
    # dump the firmware info!
    #
    with open(yamlpath, 'w') as f:
        yaml.dump(fwyaml, f)

###################################################################################################

for fpath in args.file:
    print(f'#\n# {fpath}\n#\n')

    try:
        with open(fpath, 'rb') as f:
            parsefw(f,
                Path(args.format.format(fpath=fpath, fname=fpath.name, fdir=fpath.parent))
            )

    except Exception as e:
        print('[!] Failed:', e)

    print()
