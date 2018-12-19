tinyveracrypt: VeraCrypt-compatible block device encryption setup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tinyveracrypt is a collection of command-line tools (currently Python
scripts) for Linux which can be used to create and open (mount) encrypted
volumes compatible with VeraCrypt (tested with VeraCrypt 1.17) and
`cryptsetup open --type tcrypt --veracrypt' (tested with cryptsetup 1.6.7). It
has some additional features such as plaintext UUID and volume label.

Features and plans
~~~~~~~~~~~~~~~~~~
* tinyveracrypt is easier to install from source than VeraCrypt or
  cryptsetup.
* tinyveracrypt works offline: it can be run on one machine, and the effect
  (volume creation or volume opening) happens on another machine. The latter
  machine can have less memory.
* Easy command-line interface for creating encrypted volumes (also
  compatible with the `veracrypt' command).
* Can create encrypted volumes without using extra disk space for some
  filesystems (ext2, ext3, ext4, btrfs, reiserfs, nilfs and ocfs2).
* Can create or use a plaintext FAT12 or FAT16 filesystem in front of the
  encrypted volume.
* PLANNED: Easy command-line interface.
* PLANNED: Optional volume indentification by UUID and label for blkid and
  udev.
* Nice to have: Implementation in C with only a few dependencies.

FAQ
~~~
Q1. Is tinyveracrypt ready for production use?
""""""""""""""""""""""""""""""""""""""""""""""
Yes, for encrypted volume creation (init or --create) and opening encrypted
volumes (open or --mount) on Linux. Othwerise no, currently it's barely
usable and inconvenient. If you need something which works now, use the
veracrypt command-line tool to create or open a volume, and use the
veracrypt or cryptsetup (at least >= 1.6.7) command-line tool to open a
volume.

Q2. Can tinyveracrypt create hidden volumes?
""""""""""""""""""""""""""""""""""""""""""""
Not out-of-the-box, but it is easy to add this feature.

Q3. Can tinyveracrypt create and open TrueCrypt volumes?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Yes, just specify the `--truecrypt' flag for the `init', `--create',
`open', `--mount', `get_table' etc. commands.

Q4. Does tinyveracrypt support multiple hashes and ciphers?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
No, it supports only PBKDF2 of SHA-512, and AES in XTS mode (i.e.
aes-xts-plain64). Support for others is easy to add.

The number of iterations is confiugrable though (`--pim=...'), the default
is 500000 iterations (`--pim=485') for VeraCrypt and 1000 iterations
(`--pim=-14') for TrueCrypt (`--truecrypt').

Q5. Should I use the VeraCrypt or the LUKS on-disk format?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
On Linux either one works fine. If you care about opening your encrypted
volumes on other systems (such as Mac or Windows) in the future, or you
prefer a GUI in the future, use the VeraCrypt on-disk format, because it has
those tools. The tool to open LUKS volumes, cryptsetup, is Linux-only.

LUKS has better properties when modifying or deleting key slots: it is
harder to forensically recover a deleted LUKS key than a deleted VeraCrypt
key.

Q6. Can tinyveracrypt open an encryptee volume created by
tinyveracrypt, VeraCrypt or TrueCrypt?
""""""""""""""""""""""""""""""""""""""
tinyveracrypt can open encrypted volumes created by tinyveracrypt.

tinyveracrypt can open encrypted volumes created by VeraCrypt or Truecrypy
if the volume was created with the default settings of VeraCrypt 1.17
(PBKDF2 of SHA-512, and AES in XTS mode (i.e. aes-xts-plain64)) or with the
proper settings of Truecrypt >= 5.0. More code needs to be written for
opening other kinds of volumes as well, some of them look like easy to add.

See Q21 and Q22 question how to open the volume with different tools.

Q7. Does tinyveracrypt share any code with VeraCrypt or TrueCrypt?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
No, tinyveracrypt has been written from scratch in Python.

Q8. VeraCrypt has passed a software security audit. Did it cover tinyveracrypt?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
No, it hasn't. tinyveracrypt isn't audited software. If you need audited
software for encrypted block devices, use vanilla VeraCrypt.

Q9. How to create a VeraCrypt encrypted volume?
"""""""""""""""""""""""""""""""""""""""""""""""
This functionality is available from the command-line:

  $ ./tinyveracrypt.py init RAWDEVICE

It also supports the veracrypt syntax, e.g:

  $ ./tinyveracrypt.py --text --create --quick --volume-type=normal --size=BYTESIZE --encryption=aes --hash=sha512 --filesystem=none --pim=0 --keyfiles= --random-source=/dev/urandom RAWDEVICE
  $ veracrypt          --text --create --quick --volume-type=normal --size=BYTESIZE --encryption=aes --hash=sha512 --filesystem=none --pim=0 --keyfiles= --random-source=/dev/urandom RAWDEVICE

Please note that truecrypt is not able to create a VeraCrypt encrypted
volume.

Q10. How to create TrueCrypt encrypted volume?
""""""""""""""""""""""""""""""""""""""""""""""
This functionality is available from the command-line:

  $ ./tinyveracrypt.py init --truecrypt RAWDEVICE

It also supports the truecrypt syntax, e.g:

  $ ./tinyveracrypt.py --truecrypt --text --create --quick --volume-type=normal --size=BYTESIZE --encryption=aes --hash=sha-512 --filesystem=none --keyfiles= --random-source=/dev/urandom RAWDEVICE
  $ truecrypt                      --text --create  -quick --volume-type=normal --size=BYTESIZE --encryption=aes --hash=sha-512 --filesystem=none --keyfiles= --random-source=/dev/urandom RAWDEVICE

Please note that veracrypt is not able to create a TrueCrypt encrypted
volume, it ignores the `--truecrypt' flag in `--create' mode. It will create
a VeraCrypt encrypted volume instead.

The last working version of truecrypt containing the `--create' command is
7.1a, which was released on 2012-02-07.

Q12. Can tinyveracrypt create encrypted volumes with a plaintext FAT
filesystem in front of the encrypted volume?
""""""""""""""""""""""""""""""""""""""""""""
Yes, with FAT12 and FAT16 filesystems. (FAT32 is not supported).

If you already have a (plaintext) FAT12 or FAT16 filesystem at the beginning
of the raw device, run

  $ ./tinyveracrypt.py init --ofs=fat ... RAWDEVICE

to create a VeraCrypt encrypted volume right after the FAT filesystem.

This will make the FAT filesystem unbootable, because it overwrites the
following bytes in the boot sector:

* 0...2: jump (kept intact with --salt=test)
* 3..10: OEM ID (kept intact with --salt=test)
* 63..64: first 2 bytes of boot code
* 64..509: rest of boot code (kept intact with --salt=test)
* 510..511: boot sector signature (overwritten with \x55\xaa)

It will keep these intact:

* 11..62: FAT filesystem header excluding the OEM ID
* contents (files, directories) of the FAT filesystem

If you don't have a plaintext FAT12 or FAT16 yet at the beginning of the raw
device, but you want to create one, use `--mkfat=SIZE' (e.g `--mkfat=24M')
instead of `--ofs=fat':

  $ ./tinyveracrypt.py init --mkfat=SIZE ... RAWDEVICE

Useful other flags for --mkfat=...: --fat-uuid=..., --fat-label=...,
--fat-fstype=..., --fat-rootdir-entry-count=..., --fat-cluster-size=...,
--fat-count=... .

Q13. Can tinyveracrypt create an encrypted filesystem without using extra
disk space?
"""""""""""
Don't do this unless you know what you are doing and you are ready to lose
data in case you are wrong.

This is possible to initiate with;

  $ ./tinyveracrypt.py init --ofs=0 ... RAWDEVICE

However, finishing it is tricky, because you have to make sure that the
filesystem on the encrypted volume doesn't overwrite the first 512 bytes of
the raw device. Filesystems ext2, ext3, ext4, btrfs and reiserfs, jfs, nilfs
and ocfs2 don't use the first 512 bytes, but their correspoding filesystem
creation tools (mkfs.*) usually overwrite these first 512 bytes with zeros,
thus clobbering the VeraCrypt headers, rendering subsequent open
(`veracrypt --mount --filesystem=none') operations impossible.

The solution is to write back those 512 bytes after the mkfs.* tool has
finished running. This should be automated in tinyveracrypt with som
scripting.

Q14. Can tinyveracrypt create and encrypted volume with plaintext volume
label and/or UUID, recognized by blkid?
"""""""""""""""""""""""""""""""""""""""
Not out-of-the-box, but it is easy to add this feature using set_jfs_id.py.

As a workaround, you can use

  $ ./tinyveracrypt.py init --mkfat=2K --fat-label=... --fat-uuid=... ... RAWDEVICE

, but the FAT filesystem has only a short (4-byte) UUID.

For filesystems reiserfs and btrfs, adding a volume label (16 bytes maximum)
and a full-width UUID (16 bytes) will be possible without using extra disk
space (using set_jfs_id.py in a tricky way). For filesystems ext2, ext3 and
ext4 extra disk space has to be used (except possibly with a fake 1K FAT
filesystem).

Q15. What are the dependencies of tinyveracrypt?
""""""""""""""""""""""""""""""""""""""""""""""""
For creating and examining encrypted volumes, only Python 2.x is needed.

More specific info about the Python versions: tinyveracrypt needs Python
2.5, 2.6 or 2.7 (no external package are needed), or Python 2.4 with hashlib
or pycrypto. The recommended Python version is Python 2.7 (2.7.8 or later)
with OpenSSL bindings (the _ssl module). (OpenSSL's SHA-512 implementation
has key derivation from passphrase much faster than the default SHA-512 in
Python.) tinyveracrypt doesn't work with Python 3.

For opening encrypted volumes, a Linux system with the dmsetup(8) tool (and
also the losetup(8) tool for disk images) is also needed, with root access
(e.g. sudo).

Q16. Does a VeraCrypt volume have an unencrypted UUID?
""""""""""""""""""""""""""""""""""""""""""""""""""""""
No, by design it's impossible to distinguish an encrypted VeraCrypt volume
from random garbage without knowing the passphrase.

However, tinyveracrypt can create a VeraCrypt encrypted volume with a fake
LUKS header containing an unencrypted UUID (recognized by blkid in
util-linux and Busybox):

  $ ./tinyveracrypt.py init --fake-luks-uuid=random RAWDEVICE

The LUKS (LUKS1) headers don't contain a volume label field, so it's not
possible to specify one.

The created VeraCrypt encrypted volume will not be a valid LUKS volume
though, `cryptsetup open' won't be able to open it without the `--type
tcrypt --veracrypt' flag.

Please note that this (including `--veracrypt') also works for TrueCrypt
encrypted volumes.

Q19. How to detect a VeraCrypt encrypted volume with cryptsetup?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
You need cryptsetup 1.6.7 or later.

If you know the passphrase, run this:

  $ cryptsetup tcryptDump --veracrypt RAWDEVICE

Please note that this (including `--veracrypt') also works for TrueCrypt
encrypted volumes.

Q20. How to detect a TrueCrypt encrypted volume with cryptsetup?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
You need cryptsetup 1.6.7 or later.

If you know the passphrase, run this:

  $ cryptsetup tcryptDump RAWDEVICE

Please note that for VeraCrypt encrypted volumes you'd need to specify
`--veracrypt'.

Q21. How to open a VeraCrypt encrypted volume on Linux?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""
If you know the passpohrase, run this:

  $ sudo ./tinyveracrypt.py open RAWDEVICE NAME

Alternatively, if you have VeraCrypt installed, run this:

  $ sudo veracrypt --text --mount --keyfiles= --protect-hidden=no --pim=0 --filesystem=none RAWDEVICE

If the volume was created by tinyveracrypt, alternatively run this faster
method:

  $ sudo veracrypt          --text --mount --keyfiles= --protect-hidden=no --pim=0 --filesystem=none --hash=sha512 --encryption=aes RAWDEVICE

For compatibility, tinyveracrypt supports the same syntax:

  $ sudo ./tinyveracrypt.py --text --mount --keyfiles= --protect-hidden=no --pim=0 --filesystem=none --hash=sha512 --encryption=aes RAWDEVICE

The decrypted volume will be available as /dev/mapper/veracrypt1 (or 2 etc.,
specify --slot=...).

TrueCrypt (i.e. the truecrypt command) is not able to open VeraCrypt
encrypted volumes.

Alternatively, if you have cryptsetup >= 1.6.7 installed, run this:

  $ sudo cryptsetup         open --type tcrypt --veracrypt RAWDEVICE NAME

For compatibility, tinyveracrypt supports the same syntax:

  $ sudo ./tinyveracrypt.py open --type tcrypt --veracrypt RAWDEVICE NAME

The decrypted volume will be available as /dev/mapper/DEVNAME .

Please note that both (including `--veracrypt') also work for TrueCrypt
encrypted volumes.

Q22. How to open a TrueCrypt encrypted volume on Linux?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""
If you know the passpohrase, run this:

  $ sudo ./tinyveracrypt.py open --truecrypt RAWDEVICE NAME

Alternateivel, if you have VeraCrypt installed, run this:

  $ sudo veracrypt --text --mount --truecrypt --keyfiles= --protect-hidden=no --pim=0 --filesystem=none RAWDEVICE

If the volume was created by tinyveracrypt, alternatively run this faster
method:

  $ sudo veracrypt          --text --mount --truecrypt --keyfiles= --protect-hidden=no --pim=0 --filesystem=none --hash=sha512 --encryption=aes RAWDEVICE

For compatibility, tinyveracrypt supports the same syntax:

  $ sudo ./tinyveracrypt.py --text --mount --truecrypt --keyfiles= --protect-hidden=no --pim=0 --filesystem=none --hash=sha512 --encryption=aes RAWDEVICE

Alternatively, if you have TrueCrypt installed, run this:

  $ sudo truecrypt --text --mount --keyfiles= --protect-hidden=no --filesystem=none RAWDEVICE

If the volume was created by tinyveracrypt, alternatively run this faster
method:

  $ sudo truecrypt --text --mount --keyfiles= --protect-hidden=no --filesystem=none --hash=sha-512 --encryption=aes RAWDEVICE

The decrypted volume will be available as /dev/mapper/truecrypt1 (or 2 etc.,
specify --slot).

The recommended TrueCrypt version is 7.1a (released on 2012-02-07). The latest
release, 7.2 can also open encrypted volumes.

Alternatively, if you have cryptsetup >= 1.6.7 installed, run this:

  $ sudo cryptsetup         open --type tcrypt RAWDEVICE NAME

For compatibility, tinyveracrypt supports the same syntax:

  $ sudo ./tinyveracrypt.py open --type tcrypt RAWDEVICE NAME

The decrypted volume will be available as /dev/mapper/DEVNAME .

Please note that for VeraCrypt encrypted volumes you'd need to specify
`--veracrypt'.

Q23. Which command-line VeraCrypt features are missing from tinyveracrypt?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
* hidden volume
* system volume
* keyfile
* encryption other than AES
* hash other than SHA-512
* mounting the filesystem at open time
* opening volumes on non-Linux systems (e.g. macOS or Windows)

Q24. Can tinyveracrypt convert between VeraCrypt and TrueCrypt headers, or
from LUKS?
""""""""""
Yes. To regenerate the TrueCrypt/VeraCrypt headers, open the encrypted
volume (as NAME), and then run:

  $ sudo ./tinyveracrypt.py init --opened /dev/mapper/NAME

Pass flag `--truecrypt' to `init' if you want to generate a TrueCrypt header.
Pass any flags (e.g. --mkfat=...), specify any password.

Please note that the hidden volume, if any, will be destroyed as part of
this.

Some developer documentation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ dmsetup table --showkeys rr
rr: 0 72 crypt aes-xts-plain64 a64cd0845765a19b0b5948f371f0b8c7b14da01677a10009d8b9199d511624233a54e1118dd6c9e2992e3ebae56081ca1f996c74c53f61f1a48f7fb17ddc6d5b 256 7:0 256

# ss.bin is \x00 except for the first 512 byes (encrypted veracrypt header)
# above, also the same as the first 512 bytes of rr.bin

# doesn't work (setsockopt -EBUSY) on kernel 3.13.0
# works on kernel 4.2.0
# doesn't work on kernel 2.6.35-32, lacks crypto AF_ALG
# works on both rr.bin and ss.bin

__END__
