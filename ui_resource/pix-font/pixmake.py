from PIL import Image
import struct
import argparse

###############################################################################

ap = argparse.ArgumentParser(description='Make the SBCS PIX font from an image atlas')

ap.add_argument('input', help='Input image file')

ap.add_argument('output', nargs='?', help='Output PIX font (if omitted it will be created next to the input file)')

args = ap.parse_args()

###############################################################################

chars = []

with Image.open(args.input).convert('RGB') as img:
    stcol = 0

    for col in range(img.width):
        area = None

        # find the end of a character bbox
        for row in range(img.height - 1, -1, -1):
            pix = img.getpixel((col,row))
            if pix in [(255,0,0),(0,255,255),(255,0,255)]:
                if pix == (255,0,255):
                    # ends on a previous column
                    endc = col
                else:
                    # ends on this column
                    endc = col + 1

                area = (stcol, 0, endc, row+1)
                stcol = col + 1
                break

        if area is not None:
            charpic = img.crop(area)

            chardata = []

            for brow in range(0, charpic.height, 8):
                for col in range(charpic.width):
                    val = 0

                    for drow in range(min(brow + 8, charpic.height) - brow):
                        pix = charpic.getpixel((col, brow+drow))

                        if pix in [(0,0,0),(0,255,255)]:
                            val |= 1 << drow

                    chardata.append(val)

            chars.append((charpic.size, chardata))

#------------------------------------------------------------------------------

with open(args.output if args.output is not None else args.input + '.pix', 'wb') as f:
    fheight = 0

    for (cwidth, cheight), cdata in chars:
        fheight = max(fheight, cheight)

    data = bytearray(struct.pack('<H', fheight) + bytes(len(chars) * 4))

    for i, ((cwidth, cheight), cdata) in enumerate(chars):
        struct.pack_into('>BBH', data, 2 + i*4, cwidth, len(cdata), len(data))
        data += bytes(cdata)

    f.write(data)
