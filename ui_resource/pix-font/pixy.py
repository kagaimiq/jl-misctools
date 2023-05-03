from PIL import Image
import struct, yaml, argparse

ap = argparse.ArgumentParser(description='PIX test 001')

ap.add_argument('--nchars', type=int, default=128,
                help='Count of characters in PIX file (default: %(default)d chars)')

ap.add_argument('input', type=argparse.FileType('rb'),
                help='Path to the PIX file')

ap.add_argument('output', nargs='?',
                help='Path to the output image file (if omitted, a PNG file will be created next to the PIX file)')

args = ap.parse_args()


with args.input as f:
    cheight = struct.unpack('<H', f.read(2))[0]

    chars = []
    for i in range(args.nchars):
        chars.append(struct.unpack('>BBH', f.read(4)))

    maxwidth = 0
    for cwidth, csize, caddr in chars:
        maxwidth = max(cwidth, maxwidth)

    with Image.new('L', ((maxwidth + 1) * 16 - 1, (cheight + 1) * 16 - 1), color=128) as img:
        for i, (cwidth, csize, caddr) in enumerate(chars):
            posx = (maxwidth + 1) * (i % 16)
            posy = (cheight + 1) * (i // 16)

            if csize > 0:
                f.seek(caddr)
                cdata = f.read(csize)

                for y in range(cheight):
                    for x in range(cwidth):
                        pix = cdata[x + (y // 8) * cwidth] & (0x01 << (y % 8))
                        pix = 255 if pix else 0
                        img.putpixel((x+posx, y+posy), pix)

        fname = args.output
        if fname is None: fname = f.name + '.png'
        img.save(fname)

    with Image.new('RGB', (640, 480)) as img:
        posx = 0
        posy = 0

        for c in "2017-01-01 03:34:54\nJieLi Technology\nI have a question\n\nWhy JieLi Sucks?!":
            c = ord(c)

            if c == 13: # \r
                posx = 0
                continue

            if c == 10: # \n
                posx = 0
                posy += cheight
                continue

            cwidth, csize, caddr = chars[c]

            f.seek(caddr)
            cdata = f.read(csize)

            for y in range(cheight):
                for x in range(cwidth):
                    if cdata[x + (y // 8) * cwidth] & (0x01 << (y % 8)):
                        img.putpixel((x+posx, y+posy), (255,255,0))

            posx += cwidth + 0
            if (posx+cwidth) >= img.width:
                posx = 0
                posy += cheight

        img.show()
