from PIL import Image
import struct
import argparse

###############################################################################

ap = argparse.ArgumentParser(description='Parse the SBCS PIX font and generate an image atlas')

ap.add_argument('input', help='Input PIX font')

ap.add_argument('output', nargs='?', help='Output image file (if omitted, a PNG file will be created next to the PIX file)')

args = ap.parse_args()

###############################################################################

with open(args.input, 'rb') as f:
    fheight, = struct.unpack('<H', f.read(2))

    chars = []

    lowoffset = None
    totalwidth = 0

    while True:
        cwidth, csize, coffset = struct.unpack('>BBH', f.read(4))

        # in case we hit the data section.
        if lowoffset is not None and f.tell() > lowoffset:
            break

        # calculate the total output image width
        totalwidth += max(1, cwidth)

        # in case of a valid offset determine the lowest possible offset to the data
        if coffset > 0:
            if lowoffset is None:
                lowoffset = coffset
            else:
                lowoffset = min(coffset, lowoffset)

        chars.append((cwidth, csize, coffset))


    with Image.new('RGB', (totalwidth, fheight), color=(255,255,255)) as img:
        xpos = 0

        for cwidth, csize, coffset in chars:
            f.seek(coffset)
            data = f.read(csize)

            if cwidth == 0:
                # a magenta pixel indicates the end without accounting for the column
                # this pixel is located in which is useful to indicate a zero-width character.
                img.putpixel((xpos, fheight-1), (255,0,255))
                xpos += 1
                continue

            cheight = min(fheight, (len(data) // cwidth) * 8)

            for cx in range(cwidth):
                for cy in range(cheight):
                    # data is organized as 8-pixel tall columns ordered left to right, top to bottom
                    # just like the format used by the monochome LCD/OLED/etc display controllers.
                    val = (data[cx + (cy // 8) * cwidth] >> (cy % 8)) & 1

                    if cx == cwidth-1 and cy == cheight-1:
                        # right-bottom edge of the glyph, there is the end of glyph indicator.
                        val = (0,255,255) if val else (255,0,0)
                    else:
                        # put the black pixel when there is a set bit
                        if val == 0: continue
                        val = (0,0,0)

                    img.putpixel((xpos + cx, cy), val)

            xpos += cwidth

        img.save(args.output if args.output is not None else args.input + '.png')
