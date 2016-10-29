tinyveracrypt: VeraCrypt-compatible block device encryption setup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tinyveracrypt is a collection of command-line tools (currently Python
scripts) for Linux which can be used to create and open (mount) encrypted
volumes compatible with VeraCrypt (tested with VeraCrypt 1.17) and
`cryptsetup --type tcrypt --veracrypt' (tested with cryptsetup 1.6.7). It
has some additional features such as plaintext UUID and volume label.

Features and plans
~~~~~~~~~~~~~~~~~~
* tinyveracrypt is easier to install from source than VeraCrypt or
  cryptsetup.
* tinyveracrypt works offline: it can be run on one machine, and the effect
  (volume creation or volume opening) happens on another machine. The latter
  machine can have less memory.
* PLANNED: Easy command-line interface.
* PLANNED: Optional volume indentification by UUID and label for blkid and
  udev.
* PLANNED: Implementation in C with only a few dependencies.

FAQ
~~~
Q1. Is tinyveracrypt ready for production use?
""""""""""""""""""""""""""""""""""""""""""""""
No, currently it's barely usable and inconvenient. If you need something
which works now, use the veracrypt command-line tool to create or open a
volume, and use the veracrypt or cryptsetup (at least >= 1.6.7) command-line
tool to open a volume.

Q2. Can tinyveracrypt create and open hidden volumes?
"""""""""""""""""""""""""""""""""""""""""""""""""
Not out-of-the-box, but it is easy to add this feature.

Q3. Can tinyveracrypt create and open truecrypt volumes?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Not out-of-the-box, but it is easy to add this feature.

Q4. Does tinyveracrypt support multiple hashes and ciphers?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
No, it supports only PBKDF2 with 500000 iterations of SHA-512, and AES in
XTS mode (i.e. aes-xts-plain64). Support for others is easy to add.

Q5. Should I use the VeraCrypt or the LUKS on-disk format?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
On Linux either one works fine. If you care about opening your encrypted
volumes on other systems (such as Mac or Windows) in the future, or you
prefer a GUI in the future, use the VeraCrypt on-disk format, because it has
those tools. The tool to open LUKS volumes, cryptsetup, is Linux-only.

Q6. Can tinyveracrypt open a volume created by VeraCrypt?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Yes, if the volume was created with the default settings of VeraCrypt 1.17.
It's possible to open other kinds of volumes as well, some of them is easy
to add.

Q7. Does tinyveracrypt share any code with VeraCrypt?
"""""""""""""""""""""""""""""""""""""""""""""""""""""
No, tinyveracrypt has been written from scratch in Python.

Q8. VeraCrypt has passed a software security audit. Did it cover tinyveracrypt?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
No, it hasn't. tinyveracrypt isn't audited software. If you need audited
software for encrypted block devices, use vanilla VeraCrypt.

Some developer documentation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
https://veracrypt.codeplex.com/wikipage?title=VeraCrypt%20Volume%20Format%20Specification

decrypted veracrypt header (512 bytes == 64 bytes salt + 448 bytes decrypted header; numbers are MSBFirst):
  0 + 64: salt
  64 + 4: "VERA": 56455241
  68 + 2: Volume header format version: 0005
  70 + 2: Minimum program version to open (1.11): 010b
  72 + 4: CRC-32 of the decrypted bytes 256..511: 5741849c
  76 + 16: zeros: 00000000000000000000000000000000
  92 + 8: size of hidden volume (0 for non-hidden): 0000000000000000
  100 + 8: size of decrypted volume (0x9000): 0000000000009000
  108 + 8: byte offset of the master key scope (always 0x20000): 0000000000020000
  116 + 8: size of the encrypted area within the master key scope (same as size of the decrypted volume, 0x9000): 0000000000009000
  124 + 8: flag bits (0): 00000000
  128 + 4: sector size (512 -- shouldn't it be 4096?): 00000200
  132 + 120: zeros: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
  252 + 4: CRC-32 of the decrypted bytes 64..251: b2df12c0
  256 + 64: key used in the dmsetup table (concatenated primary and secondary master keys): a64cd0845765a19b0b5948f371f0b8c7b14da01677a10009d8b9199d511624233a54e1118dd6c9e2992e3ebae56081ca1f996c74c53f61f1a48f7fb17ddc6d5b
  320 + 192: zeros: 00..00
  512: end of header

TODO: how to create?

encrypted veracrypt header (512 bytes):
  0 + 64: salt (random-generated)
  64 + 448: encrypted header

$ dmsetup table --showkeys rr
rr: 0 72 crypt aes-xts-plain64 a64cd0845765a19b0b5948f371f0b8c7b14da01677a10009d8b9199d511624233a54e1118dd6c9e2992e3ebae56081ca1f996c74c53f61f1a48f7fb17ddc6d5b 256 7:0 256

# ss.bin is \x00 except for the first 512 byes (encrypted veracrypt header)
# above, also the same as the first 512 bytes of rr.bin

# doesn't work (setsockopt -EBUSY) on kernel 3.13.0
# works on kernel 4.2.0
# doesn't work on kernel 2.6.35-32, lacks crypto AF_ALG
# works on both rr.bin and ss.bin
$ sudo ./cryptsetup open --type tcrypt --veracrypt rr.bin rr
$ sudo ./cryptsetup open --type tcrypt --veracrypt ss.bin rr

# works to mount ob both rr.bin and ss.bin
$ veracrypt-1.17-console-amd64.bin --text --keyfiles= --protect-hidden=no --filesystem=none --pim=0 ss.bin

__END__
