from jl_stuff import *
import argparse, struct, pathlib
import yaml

ap = argparse.ArgumentParser(description='BR17 firmware unpacker')

def anyint(s):
    return int(s, 0)

ap.add_argument('--chipkey', type=anyint, metavar='KEY',
                help='The chip key that is used to encrypt the firmware (default is taken from fw itself)')

ap.add_argument('file', nargs='+',
                help='Input firmware file(s)')

args = ap.parse_args()

###################################################################################################

def nullterm(data):
    pos = data.find(b'\0')
    if pos < 0: pos = len(data)
    return data[:pos]

###################################################################################################

class SydFile:
    def __init__(self, sydfs, info):
        self.sydfs = sydfs

        self.type = info['type']
        self.crc16 = info['crc16']
        self.offset = info['offset']
        self.size = info['length']
        self.number = info['number']
        self.name = str(info['name'])

        self.absoffset = self.offset + sydfs.flashbase

    def read(self, addr, size):
        if addr > self.size:
            raise ValueError('Address out of range')

        remsize = min(size, self.size - addr)
        return self.sydfs.flash.read(self.absoffset + addr, remsize)

    def __repr__(self):
        return '<[%-16s]: %8d bytes @ %08x - CRC 0x%04x, type %d, #%d>' % \
                (self.name, self.size, self.offset, self.crc16, self.type, self.number)


class SydReader:
    def __init__(self, flash, flashbase=0, headerbase=0, encrypted=True, size=None, headerless=False):
        self.flash = flash
        self.flashbase = flashbase
        self.headerbase = flashbase + headerbase
        self.encrypted = encrypted
    
        #-----------------------------------------------------------------------------------#

        if headerless:
            if size is None:
                raise TypeError('The size should be specified for a headerless syd.')

            self.listbase = self.headerbase

            nfiles = 0

            for off in range(0, size, 32):
                entry = flash.read(self.listbase + off, 32)

                # TODO, proper sanity check
                if entry[1] != 0x00:
                    break

                nfiles += 1

            self.filecount = nfiles

        else:
            fhead = flash.read(self.headerbase, 32)
            if encrypted: fhead = jl_crypt_enc(fhead)
            fhcrc, fhead = struct.unpack('<H30s', fhead)

            self.listbase = self.headerbase + 32

            if jl_crc16(fhead) != fhcrc:
                raise Exception('Flash header CRC mismatch')

            flcrc, finfo1, finfo2, fnum, fver, fver1, fctype = struct.unpack('<HIIIII8s', fhead)

            print('<SYD> list crc: %04x, Info: %08x %08x, count: %d, version: %08x %08x, chiptype: %s' % \
                  (flcrc, finfo1, finfo2, fnum, fver, fver1, fctype))

            if fnum > 1024:
                raise Exception('Too ambigous file count')

            self.filecount = fnum
            self.info = {'info': (finfo1, finfo2), 'version': (fver, fver1), 'chiptype': fctype}

            flcrc_calc = 0

            for i in range(self.filecount):
                entry = flash.read(self.listbase + 32 * i, 32)
                flcrc_calc = jl_crc16(entry, flcrc_calc)

            if flcrc_calc != flcrc:
                raise Exception('File list CRC mismatch')

    def get_file_hdr(self, fid):
        if fid < 0 or fid >= self.filecount:
            raise IndexError('File ID out of bounds')

        entry = self.flash.read(self.listbase + 32 * fid, 32)
        if self.encrypted: entry = jl_crypt_enc(entry)

        etype, eres, ecrc16, eoff, elen, enum, ename = struct.unpack('<BBHIII16s', entry)

        ename = str(nullterm(ename), 'ascii')

        info = {
            'type': etype,
            'reserved': eres,
            'crc16': ecrc16,
            'offset': eoff,
            'length': elen,
            'number': enum,
            'name': ename
        }

        return info

    def get_file_by_id(self, fid):
        return SydFile(self, self.get_file_hdr(fid))

####################################################################

class FlashFile:
    def __init__(self, file, offset=0, size=None):
        self.file = file
        self.offset = offset

        if size is not None:
            self.size = size
        else:
            oldpos = f.tell()
            self.size = f.seek(0, 2) - self.offset
            f.seek(oldpos)

    def read(self, addr, size):
        #if addr >= self.size:
        #    raise ValueError('Addressing way out of bounds')
        #elif (addr + size) >= self.size:
        #    raise ValueError('Reading way out of bounds')

        #print("\x1b[1;33m  ;; flash read - %08x %d ;;\x1b[0m" % (addr, size))
        self.file.seek(self.offset + addr)
        return self.file.read(size)

class SFC:
    def __init__(self, flash, base, key):
        self.flash = flash
        self.base = base
        self.key = key

        if base > flash.size:
            raise ValueError('Base address goes beyond the flash size')

        self.size = flash.size - base

    def read(self, addr, size):
        if False:
            data = b''

            while len(data) < size:
                baddr = addr & ~31
                boff = addr & 31

                remsize = min(32, size - len(data))
                blksize = remsize + boff

                block = self.flash.read(self.base + baddr, blksize)

                if len(block) < blksize:
                    break

                block = jl_crypt_enc(block, (self.key ^ (baddr >> 2)) & 0xffff)

                data += block[boff:][:remsize]
                addr += remsize

            return data
        else:
            data = bytearray(self.flash.read(self.base + addr, size))

            pos = 0
            while pos < size:
                caddr = addr + pos
                baddr = caddr & ~31
                boff = caddr & 31
                brem = 32 - boff

                key = (self.key ^ (baddr >> 2)) & 0xffff

                block = data[pos:pos+brem]

                if boff > 0:
                    block = jl_crypt_enc(bytes(boff) + block, key)[boff:]
                else:
                    block = jl_crypt_enc(block, key)

                data[pos:pos+brem] = block

                pos += brem

            return bytes(data)

###################################################################################################

def chipkeyfile_decode(ent):
    print('---- Chip key file ----')

    ckfile = ent.read(0, ent.size)

    hexdump(ckfile)

    if jl_crc16(ckfile) != ent.crc16:
        raise Exception('Chipkey file CRC mismatch (from file entry!)')

    # there are some extra data that goes after this file entry (32 bytes)
    ckfile = ent.sydfs.flash.read(ent.absoffset, 64)

    hexdump(ckfile)

    ckdata, ckcrc = struct.unpack_from('<32sH', ckfile, 0)

    if jl_crc16(ckdata) != ckcrc:
        raise Exception('Chipkey file CRC mismatch (from extra data!)')

    cksum = sum(ckdata[:16]) & 0xff

    if cksum >= 0xE0:
        cksum = 0xAA
    elif cksum <= 0x10:
        cksum = 0x55

    key = 0

    for i in range(16):
        v1 = ckdata[16 + i]
        v2 = ckdata[15 - i]
        vxor = v1 ^ v2

        if vxor < cksum:
            key |= (1 << i)

        # perfect cherry blossom
        print('%2d [%04x %s %04x]: %02x ^ %02x = %02x - %02x = %02x (%d)' % \
              (i, 1 << i, ">>" if vxor < cksum else "--", key,
               v1, v2, vxor, cksum, vxor - cksum, vxor < cksum))

    print('>>>>> CHIP KEY %04x <<<<<' % key)

    print('------------------------')

    return key



def parsefw(fwfile, outdir):
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
                fw_pdc = str(nullterm(block[4:]), 'ascii')
                print('--- PDC-> [%s]' % fw_pdc)

        elif fw_pdn is None:
            if block.startswith(b'pdn:'):
                fw_pdn = str(nullterm(block[4:]), 'ascii')
                print('--- PDN-> [%s]' % fw_pdn)

        else:
            break

    # naive sanity check
    if fw_pdc is None or fw_pdn is None:
        raise Exception('Missing pdc:/pdn: strings!')

    #
    # scan the syd for the important firmware parts
    #
    mainsyd = SydReader(flash)

    for n in range(mainsyd.filecount):
        ent = mainsyd.get_file_by_id(n)

        if ent.name == 'uboot.boot':
            f_uboot = ent

        elif ent.name == 'user.app':
            if f_userapp is not None:
                print(ent, f_userapp)

            f_userapp = ent

        elif ent.name == '_____.____2':
            info2syd = SydReader(flash, headerbase=ent.absoffset, encrypted=False, size=ent.size, headerless=True)

            for m in range(info2syd.filecount):
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
    if f_uboot is None:
        raise Exception('Missing uboot.boot!')

    if f_userapp is None:
        raise Exception('Missing user.app!')

    if f_syscfg is None:
        raise Exception('Missing sys.cfg!')

    if f_spcaer is None:
        raise Exception('Missing spc.aer!')

    if f_chipkey is None:
        raise Exception('Missing chipkey.bin!')

    #====================================================================#

    outdir = pathlib.Path(outdir)
    outdir.mkdir(exist_ok=True)

    yamlpath = outdir/'jlfirmware.yaml'

    fwinfo = {
        'pdc': fw_pdc,
        'pdn': fw_pdn
    }

    fwyaml = {
        'type': 'jl-firmware',
        'variant': 'br17',
        'info': fwinfo
    }

    #====================================================================#

    spcareas = None

    if f_spcaer is not None:
        ent = f_spcaer

        print('---- Special Area ----')

        spcareas = []

        for off in range(0, ent.size, 16):
            area = ent.read(off, 16)
            if len(area) < 16: break

            ainfo, acrc = struct.unpack('<14sH', area)

            if jl_crc16(ainfo) != acrc:
                break

            aname, apos, asize, axx1, axx2 = struct.unpack('<4sIIBB', ainfo)

            aname = str(aname, 'ascii')

            print('%s - @%08x (%d) - %02x %02x' % (aname, apos, asize, axx1, axx2))
            spcareas.append({'name': aname, 'pos': apos, 'size': asize, 'xx1': axx1, 'xx2': axx2})

            if apos == 0x444E4546:  # "FEND"
                print('   *** somewhere at flash end? ***')
            elif apos < flash.size:
                hexdump(flash.read(apos, 64))
            else:
                print('   *** address out of bounds ***')

    #====================================================================#

    if f_uboot is not None:
        ubootfile = outdir/f_uboot.name
        ubootfile.write_bytes(f_uboot.read(0, f_uboot.size))
        fwinfo['spl-file'] = str(ubootfile.relative_to(yamlpath.parent))

    if f_verbin is not None:
        verfile = outdir/f_verbin.name
        verfile.write_bytes(f_verbin.read(0, f_verbin.size))
        fwinfo['version-info'] = str(verfile.relative_to(yamlpath.parent))

    if spcareas is not None:
        fwinfo['special-areas'] = {}

        for area in spcareas:
            info = {
                'address': area['pos'],
                'size': area['size'],
                'arg1': area['xx1'],
                'arg2': area['xx2']
            }

            fwinfo['special-areas'][area['name']] = info

    #
    # parse user.app!
    #
    try:
        if args.chipkey is None:
            if f_chipkey is None:
                raise Exception('The chipkey.bin file is absent!')

            chipkey = chipkeyfile_decode(f_chipkey)
            fwinfo['chipkey'] = chipkey
        else:
            chipkey = args.chipkey

        print('Using chipkey: %04x' % chipkey)

        # SFC is mapped at the beginning of user.app
        sfc = SFC(flash, f_userapp.absoffset, chipkey)

        (outdir/'user.app').write_bytes(sfc.read(0, f_userapp.size))

        # grab the sys.cfg via SFC as it is encrypted alongside user.app!
        syscfg = sfc.read(f_syscfg.offset - f_userapp.offset, f_syscfg.size)

        if jl_crc16(syscfg) != f_syscfg.crc16:
            print('Syscfg CRC mismatch')
            return

        (outdir/'sys.cfg').write_bytes(syscfg)

        print('######### sys.cfg:')
        hexdump(syscfg)

        fi_flashcfg = {}
        fi_clkcfg = {}

        fwinfo['sys-cfg'] = {
            'flash-cfg': fi_flashcfg,
            'clk-config': fi_clkcfg,
        }

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

        fi_flashcfg['flash_id']      = flashcfg[0]
        fi_flashcfg['flash_size']    = flashcfg[1]
        fi_flashcfg['spi_run_mode']  = flashcfg[4]
        fi_flashcfg['spi_div']       = flashcfg[5]
        fi_flashcfg['protected_arg'] = flashcfg[7]

        # Clock config
        clkcfg = struct.unpack_from('<IIIII', syscfg, 10*4)
        print('pll_sel          = %d'   % clkcfg[0])
        print('osc_freq         = %d'   % clkcfg[1])
        print('osc_src          = %d'   % clkcfg[2])
        print('osc_hc_en        = %d'   % clkcfg[3])
        print('osc_1pin_en      = %d'   % clkcfg[4])
        print()

        fi_clkcfg['pll_sel']     = clkcfg[0]
        fi_clkcfg['osc_freq']    = clkcfg[1]
        fi_clkcfg['osc_src']     = clkcfg[2]
        fi_clkcfg['osc_hc_en']   = clkcfg[3]
        fi_clkcfg['osc_1pin_en'] = clkcfg[4]

        # Whatever
        watcfg = struct.unpack_from('<II', syscfg, 15*4)
        print('rem stuff start  = 0x%x' % watcfg[0])
        print('rem stuff length = 0x%x' % watcfg[1])
        print(' ---> %08x' % (watcfg[0] + watcfg[1]))
        print()

        print('cfg zone:')
        hexdump(flash.read(flashcfg[8] + flashcfg[6], flashcfg[9]))

        print('######### user.app:')

        #
        # finally extract data from the user.app, whose syd header starts with offset specified in sys.cfg
        #

        fwsyd = SydReader(sfc, headerbase=flashcfg[3], encrypted=False)

        appdatadir = outdir/'app-data'
        appdatadir.mkdir(exist_ok=True)

        fwinfo['app-files'] = []

        for mm in range(fwsyd.filecount):
            ent = fwsyd.get_file_by_id(mm)

            print(ent)
            hexdump(ent.read(0, 0x40))

            data = ent.read(0, ent.size)
            if jl_crc16(data) != ent.crc16:
                print('Warning: CRC16 does not match!')

            outfile = appdatadir/ent.name
            outfile.write_bytes(data)

            fwinfo['app-files'].append(str(outfile.relative_to(yamlpath.parent)))

    except Exception as e:
        print('<!> Failed to parse user app:', e)

    #
    # dump the firmware info!
    #
    with open(yamlpath, 'w') as f:
        yaml.dump(fwyaml, f)


for fwfile in args.file:
    print('\x1b[1;35m#\n# %s\n#\x1b[0m\n' % fwfile)

    try:
        with open(fwfile, 'rb') as f:
            parsefw(f, fwfile + '_unpack')

    except Exception as e:
        print('[!] Failed:', e)

    print()
