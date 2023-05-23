import argparse, crcmod
from Cryptodome.Cipher import AES

jl_crc16 = crcmod.mkCrcFun(0x11021,     initCrc=0x0000,     rev=False)
jl_crc32 = crcmod.mkCrcFun(0x104C11DB7, initCrc=0x26536734, rev=True)

################################################################################

ap = argparse.ArgumentParser(description='JieLi keyfile parser')

ap.add_argument('keyfile', nargs='+',
                help='Key file(s)')

args = ap.parse_args()

################################################################################

'''
weirdarray = (
    0x113f, 0x115f, 0x116f, 0x1177, 0x117b, 0x117d, 0x117e, 0x119f,
    0x11af, 0x11b7, 0x11bb, 0x11bd, 0x11be, 0x11cf, 0x11d7, 0x11db,
    0x11dd, 0x11de, 0x11e7, 0x11eb, 0x11ed, 0x11ee, 0x11f3, 0x11f5,
    0x11f6, 0x11f9, 0x11fa, 0x11fc, 0x123f, 0x125f, 0x126f, 0x1277,
    0x127b, 0x127d, 0x127e, 0x129f, 0x12af, 0x12b7, 0x12bb, 0x12bd,
    0x12be, 0x12cf, 0x12d7, 0x12db, 0x12dd, 0x12de, 0x12e7, 0x12eb,
    0x12ed, 0x12ee, 0x12f3, 0x12f5, 0x12f6, 0x12f9, 0x12fa, 0x12fc,
    0x131f, 0x132f
)
'''

def parseKey(path, param4=0, param5=0xa000):
    with open(path, 'rb') as f:
        kfdata = f.read(144)
        keyfile = str(kfdata, 'ascii')

    print('CRCs: <%04X-%08X>' % (jl_crc16(kfdata), jl_crc32(kfdata)))

    print('Key file: [' + keyfile + ']')

    crc_file = int(keyfile[64:72], 16)
    crc_keyf = jl_crc32(kfdata[:64])

    print('CRC32: %08x (calculated) <> %08x (in key file)' % (crc_file, crc_keyf))

    if crc_keyf != crc_file:
        raise ValueError('CRC mismatch: %08x (file) != %08x (calc)' % (crc_file, crc_keyf))

    kc_dat = bytes.fromhex(keyfile[ 0:32])
    kc_key = bytes.fromhex(keyfile[32:64])

    #print()
    print('data: [%s] / %s' % (kc_dat.hex(), kc_dat))
    print(' key: [%s] / %s' % (kc_key.hex(), kc_key))
    print()

    kc_dec = AES.new(kc_key, AES.MODE_ECB).decrypt(kc_dat)
    print('AES decrypt: [%s] / %s' % (kc_dec.hex(), kc_dec))

    kVal1 = int(kc_dec[0:4], 16)
    kVal2 = int(kc_dec[4:8], 16)

    '''
    if (kVal2 == param5) and (kVal1 != kVal2):
        if param4 != 0:
            if kVal1 != 0:
                pass

            kVal1 = weirdarray[kVal1 >> 9]
    '''

    return kVal1 << 16 | kVal2


for keyfile in args.keyfile:
    print("##############[ %s ]##############" % keyfile)

    try:
        key = parseKey(keyfile)
        print(">>> %08x" % key)
        print("---> Chip key = 0x%04X" % (key >> 16))
    except Exception as e:
        print("{!} Exception while parsing key:", e)

    print()
