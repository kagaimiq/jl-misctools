# Key file stuff

Tools to generate or parse the "key files" that contain the chipkey that can be passed to isd_download via the `-key <file>` parameter.
Useful for the isd_download's that require the chipkey to match with the one in the chip (i.e. isd_download shipped with AC692N series (version 3.5.0.9), etc.)

## keyfgen.py

The key file generator.

- `keyfgen.py <chipkey> [-o <file>]`

The usage is really simple, you simply enter the key and it makes a valid keyfile for you.

```
$ python3 keyfgen.py 0x68AF -o thenewkey
CRC: BB1B-030693E9
keyfile: [efb4894b09e9cd03d5f4a2ca50bdfd1d1a4958038bae59ea1a4958038bae59ea7dda1833]

$ python3 keyfparse.py thenewkey 
##############[ thenewkey ]##############
CRCs: <BB1B-030693E9>
Key file: [efb4894b09e9cd03d5f4a2ca50bdfd1d1a4958038bae59ea1a4958038bae59ea7dda1833]
CRC32: 7dda1833 (calculated) <> 7dda1833 (in key file)
data: [efb4894b09e9cd03d5f4a2ca50bdfd1d] / b'\xef\xb4\x89K\t\xe9\xcd\x03\xd5\xf4\xa2\xcaP\xbd\xfd\x1d'
 key: [1a4958038bae59ea1a4958038bae59ea] / b'\x1aIX\x03\x8b\xaeY\xea\x1aIX\x03\x8b\xaeY\xea'

AES decrypt: [363861666130303033326b6167616d69] / b'68afa00032kagami'
>>> 68afa000
---> Chip key = 0x68AF
```

## keyfparse.py

The key file parser.

- `keyfparse.py <file>...`

Can take multiple key files and decode them all, e.g.:

```
$ python3 keyfparse.py *.key
##############[ 0DF0-3130C206.key ]##############
CRCs: <0DF0-3130C206>
Key file: [3f23874705e52b9728bf51befbe91f437b2aa32da65be7f57b2aa32da65be7f528f8bf0b]
CRC32: 28f8bf0b (calculated) <> 28f8bf0b (in key file)
data: [3f23874705e52b9728bf51befbe91f43] / b'?#\x87G\x05\xe5+\x97(\xbfQ\xbe\xfb\xe9\x1fC'
 key: [7b2aa32da65be7f57b2aa32da65be7f5] / b'{*\xa3-\xa6[\xe7\xf5{*\xa3-\xa6[\xe7\xf5'

AES decrypt: [64656164613030302d6b6167616d692d] / b'deada000-kagami-'
>>> deada000
---> Chip key = 0xDEAD

##############[ 4A30-CD08E8F9.key ]##############
CRCs: <4A30-CD08E8F9>
Key file: [96f38cdf3dcc73e28b8ae777b34034ddb1a48d294a154979b1a48d294a154979ba8a7386]
CRC32: ba8a7386 (calculated) <> ba8a7386 (in key file)
data: [96f38cdf3dcc73e28b8ae777b34034dd] / b'\x96\xf3\x8c\xdf=\xccs\xe2\x8b\x8a\xe7w\xb3@4\xdd'
 key: [b1a48d294a154979b1a48d294a154979] / b'\xb1\xa4\x8d)J\x15Iy\xb1\xa4\x8d)J\x15Iy'

AES decrypt: [303566344130303000ffffffffffffff] / b'05f4A000\x00\xff\xff\xff\xff\xff\xff\xff'
>>> 05f4a000
---> Chip key = 0x05F4

         ......
```

