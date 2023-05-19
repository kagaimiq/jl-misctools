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

def parseKey(path):
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
    print('>>>> %04x : %04x' % (kVal1, kVal2))



for keyfile in args.keyfile:
    print("##############[ %s ]##############" % keyfile)

    try:
        parseKey(keyfile)
    except Exception as e:
        print("{!} Exception while parsing key:", e)

    print()
