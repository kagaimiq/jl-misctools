# Firmware & co. tools

This directory contains firmware-related stuff, which maybe is going to be spun off as a separate project ("jl-fwtools", perhaps? or just "jl-tools" for that matter.)

## fwunpack690.py

The unpacker for the BR17 firmware format (used by AC690x, AC691x and AC692x series, at least)

Usage: `fwunpack690.py <file> [<file> ...]`

It can take multiple firmware files and unpack them all, itno the `<file>_unpack/` sub-directories.

The generated directory structure is currently as follows:

- `jlfirmware.yaml` - The firmware structure description, its format yet to be ratified but it will be needed to repack the firmware the same way, when I finally make a packer.
- `uboot.boot` - The uboot.boot second-stage bootloader file, more-or-less being decrypted
- `ver.bin` - The version info file embedded in the firmware
- `app_data/` - Sub-directory containing all the files in the user.app region, the correct order is in the jlfirmware.yaml file.

## mkbfu.py

Maker for the BFU files, which are (/were) used for carrying firmware upgrades and whatnot.

Usage: `mkbfu.py [--load-addr ADDR] [--run-addr ADDR] [--name NAME] <input> <output>`

- `--load-addr <ADDR>`: Value of the "loader address" field, defaults to 0
- `--run-addr <ADDR>`: Value of the "run address" field, defaults to 0
- `--name <NAME>`: Image "name" (or type? more on that below), defaults to uppercase input file name
- `<input>`: Input file
- `<output>`: Output file

The "name" field is probably better referred as the "type" field, I guess.

In AC69xx this field contains either `JL_AC690X.BIN` / `JL_AC692X.BIN` for the full flash firmware images, or `BT_CFG.BIN` for the bluetooth config images.

However, in AC5xxx series, at least these names are used instead: `CODE`, `RESOURCE`, `FLASH`, `AUDLOGO`, `ALL`.
Not sure yet how `FLASH` or `ALL` differ, and what is `CODE` exactly. `AUDLOGO` probably updates the audio-logo part (`audlogo.res`?), and `RESOURCE` updates the resources (`res.res`?)

Note that the file contents are placed at 512-byte offset, and the header size is aligned to a 16-byte boundary to yield byte-exact contents as the `bfumake.exe` tool from the SDK.

## bruteforce.py

A simple SFCENC key bruteforcer, which takes a file, a reference file (to check the bruteforce against) and the offset in the source file.

This works for BR17-BR21 firmware image, although they actually contain the chipkey itself kept in a weirdly-encoded 32-byte file `chipkey.bin`,
so in this case it is redundant, as `fwunpack690.py` can extract the chipkey from that very file.

In case of BR23+ images, the beginning of the encrypted area is actually a file entry, which has a CRC of the entry itself,
which means that the bruteforce result check can be improved in order to check for this fact as well.

Usage: `bruteforce.py <reference> <file> <offset>`

- `<reference>`: Reference file - `sdram.app` or `sdk.app` for BR17/BR21 firmware, whatever for BR23+ firmware
- `<file>`: File to bruteforce on
- `<offset>`: Offset in the input file to the start of the encrypted area (or some region within, etc. Note that your reference should also contain expected contents).

## recrypt.py

The script that re-encrypts the region in the blob from one key to another (as well as encrypting or decrypting it.)

Usage: `recrypt.py <input> <output> <src key> <dst key> <start> <end>`

- `<input>`: Input file
- `<output>`: Output file
- `<src key>`: Decryption key (-1 for skipping of the "decryption")
- `<dst key>`: Encrypton key (-1 for skipping of the "encryption")
- `<start>`: Start of the encrypted blob in the file
- `<end>`: End of the encrypted blob (inclusive! If your area starts at e.g. 0xe5a0 and it is 0x1000 bytes long then specify 0xF5A0 instead of 0xF59F!)

Note that the "decryption" and "encryption" steps are the same, thus the same key may be put in opposite places, or even two keys may be XOR-ed together
and put into a single key argument, leaving the second one as `-1`.
That's merely for convenience.
