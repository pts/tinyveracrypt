tinyveracrypt: VeraCrypt-compatible block device encryption setup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tinyveracrypt is a Swiss army knife command-line tool to create VeraCrypt,
TrueCrypt and LUKS encrypted volumes, and to open (mount) them on Linux.
It's a drop-in replacement for the cryptsetup, veracrypt and truecrypt tools
for the subset of commands and flags it understands. It's implemented in
Python 2 with only standard Python modules and dmsetup(8) as dependencies.
It has some additional features such as plaintext UUID or plaintext FAT
filesystem in front of the encrypted volume.

Features
~~~~~~~~
* tinyveracrypt can create VeraCrypt, TrueCrypt and LUKS encrypted volumes
  (neither veracrypt nor cryptsetup can do all these as a single tool).
* tinyveracrypt is easier to install from source than VeraCrypt or
  cryptsetup.
* tinyveracrypt works offline: it can be run on one machine, and the effect
  (volume creation or volume opening) happens on another machine. The latter
  machine can have less memory.
* tinyveracrypt has an easy command-line interface for creating encrypted
  volumes (also compatible with the `veracrypt' and `cryptsetup' commands).
* tinyveracrypt can create encrypted volumes without using extra disk space for
  some filesystems (ext2, ext3, ext4, btrfs, reiserfs, nilfs, hfsplus,
  iso9660, udf, minux and ocfs2).
* tinyveracrypt can create or use a plaintext FAT12 or FAT16 filesystem in
  front of the encrypted volume.
* tinyveracrypt has an easy-to-use and convenient command-line interface.
* tinyveracrypt has some commands and flags compatible with `veracrypt' and
  `cryptsetup', so tinyveracrypt can be used as a drop-in replacement for
  these tools.
* tinyveracrypt is implemented in less than 5000 lines of Python 2 code,
  using only standard Python modules. It uses `dmsetup' for opening
  encrypted volumes, and no other tools for creating encrypted volumes.
* tinyveracrypt interoperates with veracrypt, truecrypt and cryptsetup:
  other tools can open encrypted volumes created by tinyveracrypt, and,
  if AES XTS encryption is used, then tinyveracrypt can also
  open encrypted encrypted volumes created by the other tools.
* tinyveracrypt can create encrypted volumes with custom header values
  (e.g. the encrypted volume can start at any offset within the raw device,
  any LUKS anti-forensic stripe count can be specified).
* tinyveracrypt can create encrypted volumes deterministically by using
  a pregenerated file as a random source.

Usage for VeraCrypt:

  $ ./tinyveracrypt.py init --type=veracrypt --size=20K veracrypt.img
  Enter passphrase:
  $ sudo ./tinyveracrypt.py open veracrypt.img myvol
  Enter passphrase:
  $ sudo dmsetup table myvol
  0 4090 crypt aes-xts-plain64 00...00 0 veracrypt.img 8 1 allow_discards
  $ sudo ./tinyveracrypt.py close myvol

Usage for TrueCrypt:

  (As above, but use --type=truecrypt instead of --type=veracrypt .)

Usage for LUKS:

  $ ./tinyveracrypt.py init --type=luks --size=2018K luks.img
  Enter passphrase:
  $ sudo ./tinyveracrypt.py open luks.img myvol
  Enter passphrase:
  $ sudo dmsetup table myvol
  0 4090 crypt aes-xts-plain64 00...00 0 luks.img 8 1 allow_discards
  $ sudo ./tinyveracrypt.py close myvol

FAQ
~~~
Q1. Is tinyveracrypt ready for production use?
""""""""""""""""""""""""""""""""""""""""""""""
Yes, for encrypted volume creation (`init' or --create), getting the
keytable (`get-table'), opening (`open', --mount or `open-table') and
closing (`close') encrypted volumes on Linux. Other features are
experimental.

Q2. Can tinyveracrypt create TrueCrypt and VeraCrypt hidden volumes?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Not implemented, but it would be easy to add this feature.

Q2B. Can tinyveracrypt open TrueCrypt and VeraCrypt hidden volumes?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Not implemented, but it would be easy to add this feature.

Q3. Can tinyveracrypt create and open TrueCrypt volumes?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Yes, just specify the `--truecrypt' or `--type=truecrypt' flag for the
`init', `--create', `open', `--mount', `get-table' etc. commands.

Q4. Does tinyveracrypt support multiple hashes and ciphers?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
No, it supports only PBKDF2 of some hashes (SHA-512, SHA-1 and whatever
Python hashlib supports, which includes SHA-256 and RIPEMD-160), and AES in
XTS mode (i.e. aes-xts-plain64). Support for others is easy to add.

The number of iterations is confiugrable (`--pim=...'), the default is
500000 iterations (`--pim=485') for VeraCrypt and LUKS, and 1000 iterations
(`--pim=-14') for TrueCrypt (`--truecrypt').

Q5. Should I use the VeraCrypt or the LUKS on-disk format?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
On Linux either one works fine. If you care about opening your encrypted
volumes on other systems (such as Mac or Windows) in the future, or you
prefer a GUI in the future, use the VeraCrypt on-disk format, because it has
those tools. The standard tool to open LUKS volumes, cryptsetup, is
Linux-only. (tinyveracrypt can also open LUKS volumes, but only on Linux.)

LUKS supports multiple passphrases per key slot, thus multiple people can
open them without telling each other their passphrase.

LUKS has better properties when modifying or deleting key slots: it is
harder to forensically recover a deleted LUKS key than a deleted VeraCrypt
key.

LUKS has a standard header format, and thus LUKS encrypted volumes can be
detected as such by /sbin/blkid and other tools. (tinyveracrypt also
supports this for VeraCrypt and TrueCrypt encrypted volumes, just create
them with `tinyveracrypt init --use-luks-uuid=random ...' etc.)

Q6. Can tinyveracrypt open an encrypted volume created by
tinyveracrypt, VeraCrypt, TrueCrypt or `cryptsetup luksFormat'?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
tinyveracrypt can open encrypted volumes created by tinyveracrypt.

tinyveracrypt can open VeraCrypt, TrueCrypt and LUKS1 encrypted volumes
(created by the `veracrypt', `truecrypt' and `cryptsetup luksFormat'
commands) if the aes-xts-plain64 cipher is used (e.g. the default of
VeraCrypt 1.17 and cryptsetup 1.7.3) and a supported hash (e.g. SHA-512,
SHA-1  and whatever Python hashlib supports, which includes SHA-256 and
RIPEMD-160) is used.

The default ciphers and hashes of VeraCrypt 1.17, TrueCrypt >= 5.0 and
cryptsetup 1.7.3 are good for all 3 encrypted volume types.

tinyveracrypt can't open or create LUKS2 encrypted volumes.

See Q21 and Q22 question how to open the volume with different tools.

Q7. Does tinyveracrypt share any code with VeraCrypt, TrueCrypt or
cryptsetup?
"""""""""""
No, tinyveracrypt has been written from scratch in Python.

Q8. VeraCrypt has passed a software security audit. Did it cover tinyveracrypt?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
No, it hasn't. tinyveracrypt isn't professionally audited software. If you need
such software for encrypted block devices, use vanilla VeraCrypt.

If you want to conduct a security audit on tinyveracrypt, please contact the
author.

Q9. How to create a VeraCrypt encrypted volume?
"""""""""""""""""""""""""""""""""""""""""""""""
This functionality is available from the command-line:

  $ ./tinyveracrypt.py init RAWDEVICE

tinyveracrypt also supports the `veracrypt --create' syntax, e.g. these are
equivalent:

  $ ./tinyveracrypt.py --text --create --quick --volume-type=normal --size=BYTESIZE --encryption=aes --hash=sha512 --filesystem=none --pim=0 --keyfiles= --random-source=/dev/urandom RAWDEVICE
  $ veracrypt          --text --create --quick --volume-type=normal --size=BYTESIZE --encryption=aes --hash=sha512 --filesystem=none --pim=0 --keyfiles= --random-source=/dev/urandom RAWDEVICE

Please note that `truecrypt' is not able to create a VeraCrypt encrypted
volume.

Q10. How to create TrueCrypt encrypted volume?
""""""""""""""""""""""""""""""""""""""""""""""
This functionality is available from the command-line:

  $ ./tinyveracrypt.py init --truecrypt RAWDEVICE

tinyveracrypt also supports the `truecrypt --create' syntax, e.g. these are
equivalent:

  $ ./tinyveracrypt.py --truecrypt --text --create --quick --volume-type=normal --size=BYTESIZE --encryption=aes --hash=sha-512 --filesystem=none --keyfiles= --random-source=/dev/urandom RAWDEVICE
  $ truecrypt                      --text --create  -quick --volume-type=normal --size=BYTESIZE --encryption=aes --hash=sha-512 --filesystem=none --keyfiles= --random-source=/dev/urandom RAWDEVICE

Please note that `veracrypt' is not able to create a TrueCrypt encrypted
volume, it ignores the `--truecrypt' flag in `--create' mode. It will create
a VeraCrypt encrypted volume instead.

The last working version of `truecrypt' containing the `--create' command is
7.1a, which was released on 2012-02-07. The first version which creates a
TrueCrypt encrypted volume which tinyveracrypt can open is 5.0.

Q11. How to create a LUKS1 encrypted volume?
""""""""""""""""""""""""""""""""""""""""""""
This functionality is available from the command-line:

  $ ./tinyveracrypt.py init --type=luks RAWDEVICE

It is mostly equivalent to:

  $ cryptsetup luksFormat --batch-mode --use-urandom --cipher=aes-xts-plain64 --hash=sha512 --key-size=512 RAWDEVICE

tinyveracrypt also supports the `cryptsetup luksFormat' syntax, e.g. these
are eqivalent.

  $ ./tinyveracrypt.py luksFormat --batch-mode --use-urandom RAWDEVICE
  $ cryptsetup         luksFormat --batch-mode --use-urandom RAWDEVICE

The default settings of `cryptsetup luksFormat' in cryptsetup 1.7.3 on
Debian are `--ciphear=aes-xts-plain64 --hash=sha256 --key-size=256',
these are the same defaults as for `cryptsetup luksFormat'.

Please note that the number of PBKDF2 iterations and the number of
anti-forensic strips is different by default in tinyveracrypt (500000) and
`cryptsetup luksFormat' (depends on CPU speed).

Please note that tinyveracrypt supports many additional customization flags
when creating LUKS encrypted volumes, e.g. `--ofs=...' (to reduce the size
of the LUKS header to as little as 4096 bytes), `--af-stripes=...',
`--pim=...' (to set the number of PBKDF2 iterations).

Q11B. How to create a LUKS2 encrypted volume?
"""""""""""""""""""""""""""""""""""""""""""""
tinyveracrypt doesn't support LUKS2.

Q12. Can tinyveracrypt create encrypted volumes with a plaintext FAT
filesystem in front of the encrypted volume?
""""""""""""""""""""""""""""""""""""""""""""
Yes, with FAT12 and FAT16 filesystems. (FAT32 and NTFS can't be supported,
see below why.)

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

If you try to boot from the raw device, you will get the following error
message:

  This is not a bootable disk.  Please insert a bootable floppy and
  press any key to try again ...

If you don't have a plaintext FAT12 or FAT16 yet at the beginning of the raw
device, but you want to create one, use `--mkfat=SIZE' (e.g `--mkfat=24M')
instead of `--ofs=fat':

  $ ./tinyveracrypt.py init --mkfat=SIZE ... RAWDEVICE

Useful other flags for --mkfat=...: --fat-uuid=..., --fat-label=...,
--fat-fstype=..., --fat-rootdir-entry-count=..., --fat-cluster-size=...,
--fat-count=... .

FAT32 (header size 90 bytes) and NTFS (header size 84 bytes) filesystems
can't be supported by --ofs=fat and --mkfat=... , because they filesystems
have a header at the beginning longer than 64 bytes, thus this header would
overlap with the VeraCrypt header at offset 64.

Q13. Can tinyveracrypt create an encrypted filesystem on a VeraCrypt or
TrueCrypt encryped volume without using any extra disk space for the
VeraCrypt or TrueCrypt header?
""""""""""""""""""""""""""""""
Don't do this unless you know what you are doing and you are ready to lose
data in case you were wrong.

If done carefully, this works with the following filesystems without data
loss: ext2, ext3, ext4, btrfs, reiserfs, jfs, nilfs, hfsplus, iso9660, udf,
minix and ocfs2, because they don't use the first 512 bytes. Some other
filesystems and data structures which don't work safely (because they use
the first 512 bytes of the raw device in their headers) include vfat, ntfs,
xfs, exfat, Linux swap, Linux RAID, LUKS.

Create the encrypted filesytem like this:

  $ dd if=/dev/zero bs=1M count=10 of=DEVICE.img
  $ sudo ./tinyveracrypt.py open-table --keytable=random --ofs=0 --end-ofs=0 DEVICE.img NAME
  $ sudo mkfs.ext2 /dev/mapper/NAME
  $ #sudo mount /dev/mapper/NAME /media/NAMEDIR  # Optional.
  $ sudo ./tinyveracrypt.py init --opened --fake-luks-uuid=random /dev/mapper/NAME
  warning: abort now, otherwise the first 512 bytes of /dev/loop0 will be overwritten, destroying filesystems such as vfat, ntfs, xfs
  warning: abort now, otherwise encryption headers on /dev/loop0 will be replaced by a new veracrypt, old passwords will be lost, encrypted data will be kept intact
  Enter passphrase:
  $ /sbin/blkid DEVICE.img
  DEVICE.img: UUID="1b564eef-2801-91f6-505c-cfd49044c8c0" TYPE="crypto_LUKS"

The advantage of this is that the UUID above is detectable without opening
the encrypted volume.

The reason why mkfs was run before `tinyveracrypt.py init' is that mkfs
(including mkfs.ext2 and mkfs.minix) would otherwise overwrite the first 512
bytes, and we want to keep there the VeraCrypt header written by
tinyveracrypt.py.

`tinyveracrypt.py init --opened' does the correct block device buffer and
page table flushing no matter the filesystem is mounted or not.

Q14. Can tinyveracrypt create and encrypted volume with plaintext volume
label and/or UUID, recognized by blkid?
"""""""""""""""""""""""""""""""""""""""
tinyveracrypt can create a VeraCrypt or TrueCrypt encrypted volume with a
fake LUKS header containing an unencrypted UUID (recognized by blkid in
util-linux and Busybox):

  $ ./tinyveracrypt.py init --fake-luks-uuid=random RAWDEVICE

The LUKS (LUKS1) headers don't contain a volume label field, so it's not
possible to specify one.

The created VeraCrypt encrypted volume will not be a valid LUKS volume
though, `cryptsetup open' won't be able to open it without the `--type
tcrypt --veracrypt' flag.

Alternatively, you can run

  $ ./tinyveracrypt.py init --mkfat=2K --fat-label=... --fat-uuid=... ... RAWDEVICE

, but the FAT filesystem has only a short (4-byte) UUID.

It would be possible to create a fake JFS filesystem (with volume label and
UUID) similar to what set_jfs_id.py does, but it's not implemented yet.

For filesystems reiserfs and btrfs, adding a volume label (16 bytes maximum)
and a full-width UUID (16 bytes) will be possible without using extra disk
space (using set_jfs_id.py in a tricky way). For filesystems ext2, ext3 and
ext4 extra disk space has to be used (except possibly with a fake 1K FAT
filesystem).

Q15. What are the dependencies of tinyveracrypt?
""""""""""""""""""""""""""""""""""""""""""""""""
For creating and examining encrypted volumes, only Python 2.x is needed.

More specific info about the Python versions: tinyveracrypt needs Python
2.5, 2.6 or 2.7 (no external package are needed), or Python 2.4 with the
package hashlib or pycrypto. (Alternatively, Python 2.4 without these
packages also works, but it is very slow: each operation may take ~30
minutes, because of slow SHA-512 computation in PBKDF2.) The recommended
Python version is Python 2.7 (2.7.8 or later) with OpenSSL bindings (the
_ssl module). (OpenSSL's SHA-512 implementation has PBKDF2 key derivation
from passphrase much faster than the default SHA-512 in Python.)
tinyveracrypt doesn't work with Python 3.

For opening encrypted volumes with tinyveracrypt, a Linux system is needed
with root access (e.g. sudo) and the dmsetup(8) tool installed. The
cryptsetup(8) tool is not needed. The losetup(8) tool is not needed if
Python has the standard fcntl module installed installed.

Q16. Does a VeraCrypt or TrueCrypt volume have an unencrypted UUID?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
No, by design it's impossible to distinguish an encrypted VeraCrypt or
TrueCrypt volume from random garbage without knowing the passphrase.

However, tinyveracrypt can create a VeraCrypt encrypted volume with a fake
LUKS header containing an unencrypted UUID (recognized by blkid in
util-linux and Busybox):

  $ ./tinyveracrypt.py init --fake-luks-uuid=random RAWDEVICE

The LUKS (LUKS1) headers don't contain a volume label field, so it's not
possible to specify one.

The created VeraCrypt encrypted volume will not be a valid LUKS volume
though, `cryptsetup open' won't be able to open it without the `--type
tcrypt --veracrypt' flag.

See Q14 more more info.

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

Q21A. How to open a LUKS1, VeraCrypt or TrueCrypt encrypted volume on Linux
(without knowning which one it is)?
"""""""""""""""""""""""""""""""""""
If you know the passphrase, run this:

  $ sudo ./tinyveracrypt.py open RAWDEVICE NAME

This only works if the encrypted volume has been created by tinyveracrypt or
with another tool with the encryption and hash settings compatible with
tinyveracrypt. See Q6 for more info on compatibility.

Q21B. How to open a LUKS1 encrypted volume on Linux?
""""""""""""""""""""""""""""""""""""""""""""""""""""
If you know the passphrase, run this:

  $ sudo ./tinyveracrypt.py open RAWDEVICE NAME

This only works if the encrypted volume was created by tinyveracrypt or with
another tool with the encryption and hash settings compatible with
tinyveracrypt. See Q6 for more info on compatibility.

Alternatively, run this:

  $ sudo cryptsetup open RAWDEVICE NAME

Q22A. How to open a VeraCrypt encrypted volume on Linux?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""
If you know the passphrase, run this:

  $ sudo ./tinyveracrypt.py open RAWDEVICE NAME

This only works if the encrypted volume was created by tinyveracrypt or with
another tool with the encryption and hash settings compatible with
tinyveracrypt. See Q6 for more info on compatibility.

Alternatively, if you have VeraCrypt installed, run this:

  $ sudo veracrypt --text --mount --keyfiles= --protect-hidden=no --pim=0 --filesystem=none RAWDEVICE

If the volume was created by tinyveracrypt, alternatively run this faster
method:

  $ sudo veracrypt          --text --mount --keyfiles= --protect-hidden=no --pim=0 --filesystem=none --hash=sha512 --encryption=aes RAWDEVICE

For compatibility, tinyveracrypt supports the same syntax:

  $ sudo ./tinyveracrypt.py --text --mount --keyfiles= --protect-hidden=no --pim=0 --filesystem=none --hash=sha512 --encryption=aes RAWDEVICE

The decrypted volume will be available as /dev/mapper/veracrypt1 (or 2 etc.,
specify --slot=...).

TrueCrypt (i.e. the `truecrypt' command) is not able to open VeraCrypt
encrypted volumes.

Alternatively, if you have cryptsetup >= 1.6.7 installed, run this:

  $ sudo cryptsetup         open --type tcrypt --veracrypt RAWDEVICE NAME

For compatibility, tinyveracrypt supports the same syntax:

  $ sudo ./tinyveracrypt.py open --type tcrypt --veracrypt RAWDEVICE NAME

The decrypted volume will be available as /dev/mapper/DEVNAME .

Please note that the commands also work for TrueCrypt
encrypted volumes, just specity `--truecrypt'.

Q22B. How to open a TrueCrypt encrypted volume on Linux?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""
If you know the passphrase, run this:

  $ sudo ./tinyveracrypt.py open --truecrypt RAWDEVICE NAME

This only works if the encrypted volume was created by tinyveracrypt or with
another tool with the encryption and hash settings compatible with
tinyveracrypt. See Q6 for more info on compatibility.

Alternatively, if you have VeraCrypt installed, run this:

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
* encryption other than aes-xts-plain64
* hash other than SHA-512 and SHA-1 (and those supported by the Python
  hashlib module, including SHA-256 and RIPEMD-160)
* mounting a filesystem at open time
* opening volumes on non-Linux systems (e.g. macOS or Windows)

Q24. Can tinyveracrypt convert between VeraCrypt and TrueCrypt headers, or
from LUKS?
""""""""""
Yes. To regenerate the TrueCrypt/VeraCrypt/LUKS header, open the encrypted
volume (as NAME), and then run:

  $ sudo ./tinyveracrypt.py init --opened /dev/mapper/NAME

Pass flag `--truecrypt' to `init' if you want to generate a TrueCrypt header
or `--type=luks' if you want to generate a LUKS header.
Pass any flags (e.g. --mkfat=...), specify any passphrase.

Please note that the hidden volume, if any, will be destroyed as part of
this.

Quick header regeneration between VeraCrypt/TrueCrypt and LUKS doesn't work,
because the iv_offset values used by the cipher are different.

Q25. Which other tools is tinyveracrypt compatible with?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""
* truecrypt (>= 5.0, tested with 7.1a): common `--create' and `--mount'
  syntax subset.

* veracrypt (tested with 1.17): common `--create' and `--mount' syntax subset.

* cryptsetup (>= 1.6.7, tested with 1.6.7, 1.7.3 and 2.0.2): common `open'
  syntax subset.

* Encrypted TrueCrypt volumes created by tinyveracrypt can be opened with
  tinyveracrypt, truecrypt, veracrypt and cryptetup.

* Encrypted VeraCrypt volumes created by tinyveracrypt can be opened with
  tinyveracrypt, veracrypt and cryptetup.

* Encrypted TrueCrypt volumes created by truecrypt or veracrypt can be
  opened with tinyveracrypt if the encrypted volume was created with
  compatible crypto and hash (see Q6 for details on compatibility).

* Encrypted VeraCrypt volumes created by veracrypt can be
  opened with tinyveracrypt if the encrypted volume was created with
  compatible crypto and hash (see Q6 for details on compatibility).

Q26. Is there a similarly compact tool like tinyveracrypt implemented in C?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
The author of tinyveracrypt knows only these tools implemented in C:
truecrypt, veracrypt and cryptsetup. None of them are as compact (small
size, few depencencies) as tinyveracrypt.

Q27. Is it possible to use LUKS and VeraCrypt on the same raw device?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Practically no, because they use a conflicting iv_offset value: LUKS1 and
LUKS2 use iv_offset == 0, VeraCrypt and TrueCrypt use iv_offset ==
data_offset (--ofs=).

Options considered (and failed) to make it work:

* --ofs=0 doesn't work with LUKS1 and cryptsetup 1.7.3 (`cryptsetup open'
  fails an an internal offset check), the minimum is --ofs=4096, see
  myluks_demo.py for creating a LUKS1 header with --ofs=4096.

* --ofs=0, VeraCrypt backup header at the end of the device (between offsets
  -131072 and -130560), LUKS1 PHDR between offsets 0 and 592, LUKS1 key
  material between 512 and 576 (overlapping the LUKS1 PHDR), using a
  filesystem which ignores the first 1024 bytes (e.g. ext2).

  This is practical only if `cryptsetup open --type tcrypt' and `veracrypt
  --mount' read the backup header by default. Unfortunately this is not the
  case, because cryptsetup needs the `--tcrypt-backup' command-line flag,
  and veracrypt doesn't have a command-line flag to read the backup header.

* --ofs=0, VeraCrypt header between offsets 0 and 512 overlapping LUKS1 PHDR
  between offsets 0 and 592.

  This doesn't work, because the VeraCrypt header and the LUKS1 PHDR overlap
  and conflict, e.g. the LUKS1 PHDR stores payload_offset between 104 and
  108, and the VeraCrypt header stores decrypted_size between 100 and 108.

* --ofs=0, VeraCrypt hidden volume header between offsets 65536 and 66048,
  LUKS1 PHDR between offsets 0 and 592, LUKS1 key material between 512 and
  576 (overlapping the LUKS1 PHDR), using a filesystem which ignores the
  first 1024 bytes (e.g. ext2).

  This works only if the user manually ignores the first 66048 bytes of the
  decrypted device, which is impractical.

Q28. What is the minimum size of a LUKS encrypted volume?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""
The minimum size of the raw device is 2018 * 1024 == 2066432 bytes, checked
by `cryptsetup open' in cryptsetup 1.7.3.

Q29. What is the minimum overhead of headers?
"""""""""""""""""""""""""""""""""""""""""""""
The minimum size of the LUKS headers (including PHDR and key material) is
4096 bytes, also checked by `cryptsetup open' in cryptsetup 1.7.3. To use
the minimum, run:

  $ ./tinyveracrypt.py init --type=luks --ofs=4096 ...

Please not that the minimum supports only 6 slots (out of 8). The minimum
for 8 slots is 5120 bytes:

  $ ./tinyveracrypt.py init --type=luks --ofs=5120 ...

Without any checks in cryptsetup, 1536 bytes would work: 1024 bytes of LUKS
PHDR, the 2nd half of it covering (overlapping with) the key material of
slot 0, plus 512 bytes of encrypted data.

The minimum size of VeraCrypt and TrueCrypt headers is 512 bytes. To use the
minimum, run:

  $ ./tinyveracrypt.py init --type=veracrypt --ofs=512 ...
  $ ./tinyveracrypt.py init --type=truecrypt --ofs=512 ...

With some filesystems (including ext2, ext3, ext4 on Linux, but excluding
ntfs and vfat) it's possible to use 0 header overhead (--ofs=0) in VeraCrypt
and TrueCrypt headers, see Q13 how.

Please note that if the header size (--ofs=...) is not a multiple of 4096
bytes, reads and writes on the encrypted volume will be slow on SSDs but
also on many HDDs because of block and page alignment issues. HDDs work well
for a multiple of 4096, but for SSDs a multiple of 1 MiB (--ofs=1M) or even
more is recommended. (By default Linux and Windows partitioning tools use 1
MiB alignment since about the beginning of 2010.) See also
https://www.thomas-krenn.com/en/wiki/Partition_Alignment .

Q30. How to create encrypted volumes tinyveracrypt in offline mode?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Example:

  $ rm -f DEVICE.img
  $ ./tinyveracrypt.py init --no-add-backup --no-truncate --size=10G DEVICE.img
  Enter passphrase:
  $ ssh root@HOST 'cat >/dev/sdX' <DEVICE.img

This will compute the VeraCrypt headers from the passphrase locally, and
transfer the resultig DEVICE.img file (of 2 MiB seemingly random data) to
the remote host HOST.

Q31. How to open encrypted volumes with tinyveracrypt in offline mode?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Run

  $ ./tinyveracrypt.py get-table --showkeys --display-device=/dev/sdX RAWDEVICE |
    ssh root@HOST dmsetup create NAME

This will get the encryption key (and offsets) from RAWDEVICE on the local
machine, and open /dev/sdX on the remote host HOST using the local
encryption key, as /dev/mapper/NAME .

`tinyveracrypt.py get-table --showkeys' is similar to `dmsetup table
--showkeys', but the former doesn't need Linux or root access, and it
doesn't create or use /dev/mapper/NAME devices.

Without the `--showkeys' flag, 00 hex bytes are displayed instead of the
real block encryption key.

Q32. Which crypto backend library does tinyveracrypt use?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""
The crypto code for aes-xts-plain64 encryption, SHA-512 and SHA-1 hashes and
key splitting to anti-forensic stripes is embedded to tinyveracrypt.py as
Python code. In addition to that, tinyveracrypt can uses hashes in the
standard hashlib Python module. To speed up AES crypto, tinyveracrypt uses
the C extensions of pycrypto or `aes', if available.

cryptsetup 1.7.3 can be compiled with any one of the supported crypto
backends such as the Linux kernel AF_ALG, gcrypt, Nettle, NSS, OpenSSL. For
the author of tinyveracrypt, the Linux kernel backend of cryptsetup didn't
work with kernel 3.13.0 (setsockopt returned EBUSY), kernel 2.6.35-32 (it
lacked AF_ALG altogether), and it worked with kernel 4.2.0.

__END__
