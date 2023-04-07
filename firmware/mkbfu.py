from jl_stuff import *
import struct, argparse, os

'''
00.07 = Magic   "JL_UDFIR"
08.0B = Header size
0C.0F = Header CRC16

--- Header contents start there:
10.13 = Data offset
14.17 = Data size
18.1B = Data CRC16
1C.1F = Loader address
20.23 = Run address
24... = File name
'''


ap = argparse.ArgumentParser(description='Jieli UpDate FIRmware / BFU file generator')

ap.add_argument('--load-addr', default='0',
                help='Value of the loader address field')

ap.add_argument('--run-addr', default='0',
                help='Value of the run address field')

ap.add_argument('--name',
                help='File name specified in the BFU file (uses uppercase input file name if not specified)')

ap.add_argument('input',
                help='Input binary file')

ap.add_argument('output',
                help='Output BFU file')

args = ap.parse_args()


with open(args.input, 'rb') as f:
    idata = f.read()


with open(args.output, 'wb') as f:
    dataoff = 0x200 # TODO

    if args.name is not None:
        name = args.name
    else:
        name = os.path.basename(args.input).upper()

    hdr = struct.pack('>IIIII',
                        dataoff, len(idata),
                        jl_crc16(idata),
                        int(args.load_addr, 0), int(args.run_addr, 0)
    )

    hdr += bytes(name, 'utf-8')
    hdr += bytes(((len(hdr) + 15) & ~15) - len(hdr))

    f.write(struct.pack('>8sII', b'JL_UDFIR', len(hdr), jl_crc16(hdr)))
    f.write(hdr)
    f.seek(dataoff)
    f.write(idata)
