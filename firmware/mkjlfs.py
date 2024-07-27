from jltech.crc import jl_crc16
from jltech.utils import *

import argparse
import struct

from pathlib import Path

################################################################################

ap = argparse.ArgumentParser(description='Make a JLFSv2 image.')

ap.add_argument('--root-dir', metavar='NAME',
                help='Encapsulate the contents in a directory called "NAME".')

ap.add_argument('--align', type=int, default=8, metavar='SIZE',
                help='Align every offset to a specified alignment, except for daisychained root (default: %(default)d bytes)')

ap.add_argument('--base', type=anyint, default=0,
                help='Specify the offset on which all entry offsets are based off. When "--root-daisychain" is specified, this option has no effect.')

ap.add_argument('--root-daisychain', action='store_true',
                help='Daisy-chain the entries on the root (put the entry\'s header along with its data following immediatly after, repeated for subsequent entry)')

ap.add_argument('--dc-align', type=int, metavar='SIZE', default=1,
                help='Align the daisychained root entries to the specified alignment.')

ap.add_argument('--dc-first-off', type=anyint, metavar='OFF',
                help='Specify the offset value for the first daisychained entry.')

ap.add_argument('--dc-offset', type=anyint, metavar='OFF', default=0x20,
                help='Specify the offset value put into all daisychained entries\' headers (default: 0x%(default)x)')

ap.add_argument('--dc-terminate', action='store_true',
                help='Terminate the last daisychained entry')

ap.add_argument('output', type=Path,
                help='Output jlfs image file')

ap.add_argument('input', type=Path, nargs='+',
                help='One or more input files or directories (directories will be recursively scanned and nested jlfs structures will be created)')

args = ap.parse_args()

################################################################################

ATTR_FILE = 0x02
ATTR_DIR  = 0x03

#
# two things doing almost the same thing
#

class JLFSmaker:
    def __init__(self, base=0, align=1):
        self.base = base
        self.align = align
        self.entries = []

    def append(self, name, attr, data):
        self.entries.append((name, attr, data))

    def __len__(self):
        size = align_to(len(self.entries) * 32, self.align)

        for name, attr, data in self.entries:
            if isinstance(data, Path):
                dsize = data.stat().st_size
            else:
                dsize = len(data)

            size += align_to(dsize, self.align)

        return size

    def __bytes__(self):
        hdata = b''
        odata = b''

        # offset to data
        doffset = self.base + align_to(len(self.entries) * 32, self.align)

        for i, (name, attr, data) in enumerate(self.entries):
            if isinstance(data, JLFSmaker):
                # adjust the base address
                data.base = doffset

            if isinstance(data, Path):
                data = data.read_bytes()
            elif not isinstance(data, (bytes, bytearray)):
                data = bytes(data)

            print(f'-- {name} @{doffset:08X} ({len(data)}) == {attr:02X}')


            header = struct.pack('<HIIBBH16s', 
                                 jl_crc16(data), 
                                 doffset,
                                 len(data),
                                 attr, 0xff,
                                 0 if i < len(self.entries)-1 else 1,
                                 name
                                 )

            hdata += struct.pack('<H30s', jl_crc16(header), header)

            odata += data
            odata += b'\xff' * align_by(len(data), self.align)

            doffset += align_to(len(data), self.align)

        hdata += b'\xff' * align_by(len(hdata), self.align)

        return hdata + odata

class JLFSdaisychain:
    def __init__(self, offset=0x20, firstoff=None, align=1, terminate=False):
        self.offset = offset
        self.first_offset = offset if firstoff is None else firstoff
        self.align = align
        self.terminate = terminate
        self.entries = []

    def append(self, name, attr, data):
        self.entries.append((name, attr, data))

    def __len__(self):
        size = len(self.entries) * 32

        for name, attr, data in self.entries:
            if isinstance(data, Path):
                dsize = data.stat().st_size
            else:
                dsize = len(data)

            size += align_to(dsize, self.align)

        return size

    def __bytes__(self):
        odata = b''

        for i, (name, attr, data) in enumerate(self.entries):
            if isinstance(data, JLFSmaker):
                data.base = 32 # always relative to the header

            if isinstance(data, Path):
                data = data.read_bytes()
            elif not isinstance(data, (bytes, bytearray)):
                data = bytes(data)

            header = struct.pack('<HIIBBH16s', 
                                 jl_crc16(data), 
                                 self.first_offset if i == 0 else self.offset,
                                 len(data) + 32,
                                 attr, 0xff,
                                 0 if (i < len(self.entries)-1) or (not self.terminate) else 1,
                                 name
                                 )

            odata += struct.pack('<H30s', jl_crc16(header), header)
            odata += data
            odata += b'\xff' * align_by(len(data), self.align)

        return odata

###############################################################################

def jlfsname(name):
    return name.encode('gb2312')[:16]


if args.root_daisychain:
    root = JLFSdaisychain(args.dc_offset, args.dc_first_off, args.dc_align, args.dc_terminate)
else:
    root = JLFSmaker(args.base, args.align)


def scan_and_populate(dest, flist):
    for fpath in flist:
        if fpath.is_dir():
            # a regular jlfs maker (who needs daisychaining one?!)
            ddir = JLFSmaker(0, args.align)
            scan_and_populate(ddir, fpath.iterdir())
            dest.append(jlfsname(fpath.name), ATTR_DIR, ddir)
        else:
            dest.append(jlfsname(fpath.name), ATTR_FILE, fpath)


if args.root_dir is not None:
    rdir = JLFSmaker(0, args.align)
    scan_and_populate(rdir, args.input)
    root.append(jlfsname(args.root_dir), ATTR_DIR, rdir)
else:
    scan_and_populate(root, args.input)


with open(args.output, 'wb') as f:
    f.write(bytes(root))
