# Key file stuff

Tools for generating and parsing the key files which contain the chip key, which is then passed
to isd_download with the `-key` parameter.

- [keyfgen.py](keyfgen.py): key file generator
  * keyfgen.py <chipkey> [-o <file>]
- [keyfparse.py](keyfparse.py): key file parser
  * keyfparse.py <file>...
