from jltech.crc import jl_crc16
import argparse, struct, pathlib
import yaml

ap = argparse.ArgumentParser(description='tone.cfg file maker')

ap.add_argument('info',
                help='Input yaml file with info')

ap.add_argument('file',
                help='Output tone.cfg file')

args = ap.parse_args()

###################################################################################################

def toneidx_make(names, idxbase=1):
    #
    # build a header
    #
    thdr = struct.pack('<6sI', b'\xff' * 6, len(names))
    thdr = struct.pack('<4sH10s', b'TIDX', jl_crc16(thdr), thdr)

    #
    # build the list
    #
    tlist = b''

    for i, name in enumerate(names):
        # entry name (null-terminated)
        ent = bytes(name, 'ascii') + b'\0'
        # append length and index
        ent = struct.pack('<BB', len(ent) + 4, idxbase + i) + ent
        # append the CRC and add to the list
        tlist += struct.pack('<H', jl_crc16(ent)) + ent

    #
    # stitch together
    #
    return thdr + tlist

###################################################################################################

# TODO: reuse the jlfs maker from mkjlfs.py or simply abandon this thing
# in favor of mkjlfs.py + this thing just making the tone.idx file.
# or do something better like automatic format conversion etc.

class Sydv2maker:
    def __init__(self, max_size=0xffffffff, alignment=16):
        self.max_size = max_size
        self.alignment = alignment

        self.files = []

    def add(self, name, data, flag=0x82):
        info = {'name': name, 'data': data, 'flag': flag}

        #
        # Get data size
        #
        if isinstance(data, (bytes, bytearray)):
            info['size'] = len(data)
        elif isinstance(data, pathlib.Path):
            info['size'] = data.stat().st_size
        elif isinstance(data, Sydv2maker):
            info['size'] = data.size
        else:
            raise TypeError('Invalid data type: %s' % type(data).__name__)

        #
        # Get aligned data size
        #
        alsize = info['size']
        if alsize % self.alignment:
            alsize += self.alignment - (alsize % self.alignment)
        info['alsize'] = alsize

        self.files.append(info)

    @property
    def size(self):
        # headers
        size = len(self.files) * 32

        # files
        for file in self.files:
            size += file['alsize']

        return size

    def dump(self, offbase=0, inclhdrsz=False):
        hdrdata = b''
        fdata = b''

        hdrsize = len(self.files) * 32
        off = offbase + hdrsize

        for i, file in enumerate(self.files):
            data = file['data']

            if isinstance(data, pathlib.Path):
                data = data.read_bytes()
            elif isinstance(data, Sydv2maker):
                data = data.dump(offbase=off)

            hdr = struct.pack('<HIIBBH16s',
                            jl_crc16(data), off, len(data) + (hdrsize if inclhdrsz else 0), # TODO! that's bad
                            file['flag'], 0xff, 1 if (i + 1) == len(self.files) else 0,
                            bytes(file['name'], 'ascii'))
 
            hdrdata += struct.pack('<H30s', jl_crc16(hdr), hdr)

            fdata += data
            fdata += b'\xff' * (file['alsize'] - len(data))

            off += file['alsize']

        return hdrdata + fdata

###################################################################################################

#
# Load the tone config info
#
with open(args.info) as f:
    info = yaml.load(f, Loader=yaml.SafeLoader)

if info.get('type') != 'tone-config':
    print('This yaml info file is not about the Tone configs!')
    exit(1)

if 'tones' not in info:
    print('The tone list is missing.')
    exit(1)

#
# Do initial parsing
#
tones = {}

for name in info['tones']:
    tone = info['tones'][str(name)]

    if 'file' not in tone:
        print('Missing file for tone "%s", skipping.' % tone)
        continue

    fpath = pathlib.Path(args.info).parent / tone['file']

    if not fpath.exists():
        print('Warning: file for tone "%s" (%s) does not exist, skipping.' % (name, fpath))
        continue

    fname = fpath.name.lower()
    fname, fext = fname.split('.', maxsplit=1)      # might be broken

    if name in tones:
        print('Tone "%s" already exists, skipping.' % name)
        continue

    tones[name] = {'fname': name + '.' + fext, 'file': fpath}

#
# Make a "index.idx" file
#
toneidx = toneidx_make([name for name in tones])

print('%d tones:' % len(tones), ', '.join([name for name in tones]))

#
# Write out into file
#
with open(args.file, 'wb') as f:
    tonedir = Sydv2maker()

    tonedir.add('index.idx', toneidx)

    for name in tones:
        tone = tones[name]
        tonedir.add(tone['fname'], tone['file'])

    subdir = Sydv2maker()
    subdir.add('tone', tonedir, flag=0x83)
    f.write(subdir.dump(inclhdrsz=True))

    print('Size:', subdir.size)
