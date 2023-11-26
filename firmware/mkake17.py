from jl_stuff import *
import argparse, struct

########################################

ap = argparse.ArgumentParser(description='JieLi boot imager (ultra limited) - BR17 ed')

def anyint(s):
    return int(s, 0)

ap.add_argument('input', type=argparse.FileType('rb'),
                help='Input file')

ap.add_argument('output', type=argparse.FileType('wb'),
                help='Output file')

ap.add_argument('--addr', type=anyint, default=0x2000,
                help='Load&run address (default: 0x%(default)x)')

args = ap.parse_args()

########################################

#def jl_crypt_enc(data):
#    return data

with args.output as of:
    with args.input as f:
        data = f.read()

    bhdr = struct.pack('<HHIIH',
        # bank count
        1,
        # bank size
        len(data),
        # bank address
        args.addr,
        # data offset
        0x10,
        # data CRC16
        jl_crc16(data)
    )
    bhdr = struct.pack('<14sH', bhdr, jl_crc16(bhdr))

    fhdr = struct.pack('<BBHIII16s',
        # file type
        1,
        # <reserved>
        0,
        # data CRC16
        jl_crc16(bhdr+data),
        # data offset
        0x40,
        # data length
        len(bhdr+data),
        # file index
        0,
        # file name
        b'jielitechno.exe'
    )

    fhdr = jl_crypt_enc(fhdr)

    hdr = struct.pack('<HIIIIIII',
        # file list CRC16
        jl_crc16(fhdr),
        # info 1
        0x4d495a55,
        # info 2
        0xdeadbeef,
        # file count
        1,
        # version 1
        0x18072019,
        # version 2
        0x07072007,
        # chip type 1
        0xacebeca0,
        # chip type 2
        0xbecaace0
    )
    hdr = struct.pack('<H30s', jl_crc16(hdr), hdr)

    # file list
    of.write(jl_crypt_enc(hdr))
    of.write(fhdr)

    # bankcb file
    of.write(jl_crypt_enc(bhdr))
    of.write(jl_crypt_enc(data))
