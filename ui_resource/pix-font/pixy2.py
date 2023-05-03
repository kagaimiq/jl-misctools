from PIL import Image
import struct, yaml, argparse

ap = argparse.ArgumentParser(description='PIX test')

ap.add_argument('pixfile', type=argparse.FileType('rb'),
                help='Path to the PIX file')

args = ap.parse_args()


with args.pixfile as f:
    csize, bs1, be1, bs2, be2 = struct.unpack('<HBBBB', f.read(6))

    bn1 = be1 - bs1 + 1
    bn2 = be2 - bs2 + 1

    with Image.new('L', ((csize + 1) * bn2 - 1, (csize + 1) * bn1 - 1), color=128) as img:
        for bt1 in range(bn1):
            for bt2 in range(bn2):
                posx = (csize + 1) * bt2
                posy = (csize + 1) * bt1

                cdata = f.read(csize * ((csize + 7) // 8))

                print('%02x %02x - %d,%d - %s' % (bt1+bs1,bt2+bs2, posx,posy, cdata.hex()))

                for y in range(csize):
                    for x in range(csize):
                        pix = cdata[x + (y // 8) * csize] & (0x01 << (y % 8))
                        pix = 255 if pix else 0
                        img.putpixel((x+posx, y+posy), pix)

        img.show()
