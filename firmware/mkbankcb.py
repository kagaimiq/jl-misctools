from jltech.crc import jl_crc16
from jltech.utils import *

import argparse
import struct
import os

###############################################################################

ap = argparse.ArgumentParser(description='Make a BankCB image')

ap.add_argument('-B', dest='endian', const='>', default='<', action='store_const',
                help='Encode bank header data in big-endian instead of little-endian default')

ap.add_argument('output',
                help='Output file path')

ap.add_argument('input', metavar='addr file', nargs='+',
                help='Load address and bank data file. The first bank is the "master bank", followed by additional banks.')

args = ap.parse_args()

###############################################################################

banks = []

for i in range(0, len(args.input), 2):
    inp = args.input[i : i+2]
    if len(inp) < 2:
        print('Incomplete definition for', inp)
        exit(1)

    addr, fpath = inp

    try:
        addr = anyint(addr)
    except ValueError:
        print(f'Load address "{addr}" is not a number')
        exit(1)

    if not os.path.exists(fpath):
        print(f'Bank file "{fpath}" does not exist')
        exit(1)

    banks.append((addr, fpath))

###############################################################################

with open(args.output, 'wb') as f:
    bank_hdr_fmt  = args.endian + '14sH'
    bank_hdrc_fmt = args.endian + 'HHIIH'
    bank_max_size = 0xffff
    bank_hdr_size = struct.calcsize(bank_hdr_fmt)

    #----------------------------------------------------

    headers = bytearray(len(banks) * bank_hdr_size)

    f.seek(len(headers))

    for i, (bload, bfile) in enumerate(banks):
        if i == 0:
            # master bank has the bank count
            bankid = len(banks)
        else:
            # other banks have their ID there
            bankid = i - 1

        with open(bfile, 'rb') as bf:
            data = bf.read()

        if len(data) > bank_max_size:
            print(f'Bank {i} is too big ({len(data)} bytes), maximum is {bank_max_size} bytes per bank.')
            break

        dataoff = f.tell()
        datacrc = jl_crc16(data)

        f.write(data)

        print(f'[{i}]: {bankid} - load @{bload:X}, data @{dataoff:X} - {len(data)} bytes, CRC: ${datacrc:04X}')

        hdr = struct.pack(bank_hdrc_fmt, bankid, len(data), bload, dataoff, datacrc)
        struct.pack_into(bank_hdr_fmt, headers, i * bank_hdr_size, hdr, jl_crc16(hdr))

    f.seek(0)
    f.write(headers)
