# Key file stuff

Tools dealing with the `.key` files used to carry the "chip key" used by e.g. isd_download in order to be able to flash a chip that has a programmed chip key (i.e. chipkey not being 0xffff).

## keyfgen.py

The key file generator.

- `keyfgen.py <chipkey> [-o <file>]`

The usage is really simple, you simply enter the key and it makes a valid keyfile for you.

```
$ python3 keyfgen.py 0xbaca -o baca.key
CRC: 4673-4A413FAD
keyfile: [d455e95927367bd753c27c6773c8bdb5c8c0d08b4580238cc8c0d08b4580238c35966a6b]

$ python3 keyfparse.py baca.key 
##############[ baca.key ]##############
CRC: <4673-4A413FAD>
file: d455e95927367bd753c27c6773c8bdb5c8c0d08b4580238cc8c0d08b4580238c35966a6b
data: b'BACAA000\x00\xff\xff\xff\xff\xff\xff\xff'
val1=BACA, val2=A000
Chip key: >>> 0xBACA <<<
```

## keyfparse.py

The key file parser.

- `keyfparse.py <file>...`

Can take multiple key files and decode them all, e.g.:

```
$ python3 keyfparse.py *.key 
##############[ 0DF0-3130C206.key ]##############
CRC: <0DF0-3130C206>
file: 3f23874705e52b9728bf51befbe91f437b2aa32da65be7f57b2aa32da65be7f528f8bf0b
data: b'deada000-kagami-'
val1=DEAD, val2=A000
Chip key: >>> 0xDEAD <<<

##############[ 4A30-CD08E8F9.key ]##############
CRC: <4A30-CD08E8F9>
file: 96f38cdf3dcc73e28b8ae777b34034ddb1a48d294a154979b1a48d294a154979ba8a7386
data: b'05f4A000\x00\xff\xff\xff\xff\xff\xff\xff'
val1=05F4, val2=A000
Chip key: >>> 0x05F4 <<<

##############[ baca.key ]##############
CRC: <4673-4A413FAD>
file: d455e95927367bd753c27c6773c8bdb5c8c0d08b4580238cc8c0d08b4580238c35966a6b
data: b'BACAA000\x00\xff\xff\xff\xff\xff\xff\xff'
val1=BACA, val2=A000
Chip key: >>> 0xBACA <<<
```
