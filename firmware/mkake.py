import argparse, struct
import crcmod

########################################

jl_crc16 = crcmod.mkCrcFun(0x11021, rev=False, initCrc=0x0000, xorOut=0x0000)

def jl_crypt_enc(data, key=0xffff):
    data = bytearray(data)

    for i in range(len(data)):
        data[i] ^= key & 0xff
        key = ((key << 1) ^ (0x1021 if (key >> 15) else 0)) & 0xffff

    return bytes(data)

########################################

ap = argparse.ArgumentParser(description='JieLi boot imager (ultra limited)')

def anyint(s):
    return int(s, 0)

ap.add_argument('input', type=argparse.FileType('rb'),
                help='Input file')

ap.add_argument('output', type=argparse.FileType('wb'),
                help='Output file')

ap.add_argument('--addr', type=anyint, default=0x12000,
                help='Load&run address (default: 0x%(default)x)')

ap.add_argument('--vid', default='7.13',
                help='V(ersion)ID string (default "%(default)s")')

ap.add_argument('--pid', default='ibukisuika12376',
                help='P(roduct)ID string (default "%(default)s")')

args = ap.parse_args()

########################################

#def jl_crypt_enc(data):
#    return data

with args.output as of:
    hdr = struct.pack('<HH4sIBBBB16s',
        # header CRC16 (stuff)
        0xdead,
        # burner size
        0,
        # version id
        bytes(args.vid, 'ascii'),
        # flash size
        0,
        # fs veresion
        1,
        # block alignment
        0,
        # <reserved>
        0,
        # special option flag
        0,
        # product id
        bytes(args.pid, 'ascii')
    )

    chdr = jl_crypt_enc(hdr)
    mhdr = (hdr[:4] + chdr[4:8] + hdr[8:16] + chdr[16:])[2:]

    hdr = struct.pack('<H30s', jl_crc16(mhdr), mhdr)
    of.write(jl_crypt_enc(hdr))

    ################################

    with args.input as f:
        data = f.read()

    hdr = struct.pack('<HHIIH',
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
    hdr = struct.pack('<14sH', hdr, jl_crc16(hdr))

    fhdr = struct.pack('<HIIBBH16s',
        # data CRC16
        jl_crc16(hdr+data),
        # data offset
        0x40,
        # data length
        len(hdr+data),
        # attributes
        0x00,
        # <reserved>
        0,
        # file index
        0xffff,
        # file name
        b'jielitechno.exe'
    )
    fhdr = struct.pack('<H30s', jl_crc16(fhdr), fhdr)

    of.write(jl_crypt_enc(fhdr))

    of.write(jl_crypt_enc(hdr))
    of.write(jl_crypt_enc(data))
