tinyveracrypt: versatile and compatible block device encryption setup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tinyveracrypt is a Swiss army knife command-line tool to create VeraCrypt,
TrueCrypt and LUKS encrypted volumes, and to open (mount) them on Linux.
It's a drop-in replacement for the cryptsetup, veracrypt and truecrypt tools
for the subset of commands and flags it understands. It's implemented in
Python 2 with only standard Python modules and dmsetup(8) as dependencies.
It has some additional features such as plaintext UUID, plaintext FAT
filesystem in front of the encrypted volume and volume creation with old
ciphers compatible with old TrueCrypt.

Features
~~~~~~~~
* tinyveracrypt can create VeraCrypt, TrueCrypt and LUKS encrypted volumes
  (none of veracrypt, truecrypt and cryptsetup can do all these as a single
  tool).
* tinyveracrypt is easier to install from source than VeraCrypt or
  cryptsetup (it just works with the system Python on most Linux systems).
* tinyveracrypt works offline: it can be run on one machine, and the effect
  (volume creation or volume opening) happens on another machine. The latter
  machine can have less memory.
* tinyveracrypt has an easy command-line interface for creating encrypted
  volumes (also compatible with the `veracrypt' and `cryptsetup' commands).
* tinyveracrypt can create encrypted volumes without using extra disk space
  for some filesystems (ext2, ext3, ext4, btrfs, reiserfs, nilfs, hfsplus,
  iso9660, udf, minux and ocfs2).
* tinyveracrypt can create or use a plaintext FAT12 or FAT16 filesystem in
  front of the encrypted volume.
* tinyveracrypt has an easy-to-use and convenient command-line interface,
  it doesn't engage in a dialog with the user except for asking for the
  passphrase.
* tinyveracrypt has some commands and flags compatible with `veracrypt' and
  `cryptsetup', so tinyveracrypt can be used as a drop-in replacement for
  these tools.
* tinyveracrypt is implemented in less than 6000 lines of Python 2 code,
  using only standard Python modules. It uses `dmsetup' for opening
  encrypted volumes, and no other tools for creating encrypted volumes.
* tinyveracrypt interoperates with veracrypt, truecrypt and cryptsetup:
  other tools can open encrypted volumes created by tinyveracrypt, and,
  if the supported cipher and hash is used, then tinyveracrypt can also
  open encrypted encrypted volumes created by the other tools.
* tinyveracrypt can create encrypted volumes with custom header values
  (e.g. the encrypted volume can start at any offset within the raw device,
  any LUKS anti-forensic stripe count can be specified, compatibility with
  old versions of TrueCrypt can be requested).
* tinyveracrypt can create encrypted volumes deterministically by using
  a pregenerated file as a random source.
* tinyveracrypt can recover a corrupt volume header (including setting a new
  passphrase without knowing any of the old passphrases) if the encrypted
  volume is currently open.
* tinyveracrypt can convert between TrueCrypt and VeraCrypt headers (without
  reencrypting) if the cipher and other parameters match matches. In some
  obscure special cases, it can also convert from/to LUKS.

See FAQ entry Q23 for features of cryptsetup, VeraCrypt and TrueCrypt not
supported by tinyveracrypt.

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

To get a full description of the supported command-line flags:

  $ ./tinyveracrypt.py --help-flags

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
Yes, but not as many as cryptsetup (LUKS) or TrueCrypt or VeraCrypt.

Supported ciphers:

* (TL;DR The highest security, recommended and default cipher is
  aes-xts-plain64, the rest are listed in decreasing order of security.)
* (TL;DR Supports all AES-based ciphers supported by VeraCrypt and TrueCrypt,
  plus the most common AES-based ciphers used with LUKS1. Doesn't support
  non-AES-based ciphers such as serpent, twofish, camellia, kuznyechik,
  cast5, des3_ede, blowfish_le, and cascades: multiple ciphers combined.
  Doesn't support cipher modes *-cbc-tcrypt and *-cbci-tcrypt, because they
  correspond to non-AES-based ciphers or cascades.)
* aes-xts-plain64. This is the default and the most common for TrueCrypt
  (7.1a, >= 5.0), VeraCrypt (1.17) and LUKS1 (cryptsetup >= 1.6.0,
  cryptsetup 2.1.0). For TrueCrypt and VeraCrypt encrypted volumes,
  tinyveracrypt supports only this cipher.
* aes-cbc-essiv:sha256. This used to be most common for
  LUKS1 (earlier versions of cryptsetup). This was the default in
  cryptsetup < 1.6.0. A bit less secure than aes-xts-plain64 (see
  explanation in the cryptsetup FAQ
  https://salsa.debian.org/cryptsetup-team/cryptsetup/blob/master/FAQ ).
* aes-lrw-benbi. Used by TrueCrypt >= 4.1, < 5.0. All aes-* other then this
  was deprecated in TrueCrypt 4.3.
* aes-cbc-plain64. Less secure than aes-cbc-essiv:sha256, see cryptsetup FAQ
  entry 5.14 on https://salsa.debian.org/cryptsetup-team/cryptsetup/blob/master/FAQ
  : ``Why was the default aes-cbc-plain replaced with aes-cbc-essiv?''
* aes-cbc-plain64be: Similar to aes-cbc-plain64, but with big endian sector
  number serialization. Has the same security problem.
* aes-cbc-plain. Same as aes-cbc-plain, but supports only encrypted volumes
  up to 2 TiB. This was the default in cryptsetup 1.0.
* aes-cbc-tcw. Used first by TrueCrypt (before version 4.1). Has the same
  fingerprinting problem as aes-cbc-plain64.
* aes-lrw-essiv:sha256. Supported for completeness only. Has a weird IV
  generation. Use aes-lrw-benbi instead.
* aes-lrw-plain64. Supported for completeness only. Has a weird IV
  generation. Use aes-lrw-benbi instead.
* aes-lrw-plain. Supported for completeness only. Has a weird IV
  generation. Use aes-lrw-benbi instead.
* aes-xts-plain: Inferior, 32-bit sector offset version of aes-xts-plain64.
* aes-xts-plain64be: Similar to aes-xts-plain64, but stores the sector
  number in big endian order in the IV. Use aes-xts-plain64 instead.
* aes-xts-essiv:sha256: Like aes-xts-plain64, but with more complicated and
  slower (but not more secure) IV generator. Use aes-xts-plain64 instead.

Supported hashes:

* (TL;DR The recommended and default hash is SHA-512.)
* (TL;DR Supports all hashes supported by VeraCrypt and TrueCrypt (except
  for streeblog, which is supported by VeraCrypt), plus the most common hashes
  used with LUKS1.)
* sha512 (SHA-512)
* sha384 (SHA-384)
* sha256 (SHA-256)
* sha224 (SHA-224)
* sha1 (SHA-1)
* ripemd160 (RIPEMD-160)
* whirlpool (Whirlpool)
* whatever Python hashlib supports (which includes ripemd160 and whirlpool,
  so including these all hashes used by VeraCrypt and TrueCrypt are supported)

Supported key derivation (secret-to-key):

* PBKDF2. TrueCrypt, VeraCrypt and LUKS1 only supports this.

  The number of iterations is confiugrable (`--pim=...'), the default is
  500000 iterations (`--pim=485') for VeraCrypt and LUKS, and 1000 iterations
  (`--pim=-14') for TrueCrypt (`--truecrypt').

Supported other algoritms:

* key splitting to anti-forensic stripes (AFSplit): For LUKS.

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
them with `tinyveracrypt.py init --use-luks-uuid=random ...' etc.)

Q6. Can tinyveracrypt open an encrypted volume created by
tinyveracrypt, VeraCrypt, TrueCrypt or `cryptsetup luksFormat'?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
tinyveracrypt can open encrypted volumes created by tinyveracrypt.

tinyveracrypt can open VeraCrypt, TrueCrypt and LUKS1 encrypted volumes
(created by the `veracrypt', `truecrypt' and `cryptsetup luksFormat'
commands) if the cipher and hash is suppored (see Q4).
The default ciphers and hashes of VeraCrypt 1.17, TrueCrypt >= 5.0 and
cryptsetup 1.7.3 are good for all 3 encrypted volume types.

tinyveracrypt can't open or create LUKS2 encrypted volumes. cryptsetup <
2.1.0 create LUKS1 encrypted volumes by default, and cryptsetup 2.1.0 >=
create LUKS2 by default (but can be changed with --type=luks1).

See Q21 and Q22 question how to open the volume with different tools.

Q7. Does tinyveracrypt share any code with VeraCrypt, TrueCrypt or
cryptsetup?
"""""""""""
No, tinyveracrypt has been written from scratch in Python.

Q8. VeraCrypt has passed a software security audit. Did it cover tinyveracrypt?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
No, it hasn't. tinyveracrypt isn't professionally audited or certified (e.g.
FIPS-140-2) software. If you need such software for encrypted block devices,
use vanilla VeraCrypt.

If you want to conduct a security audit on tinyveracrypt, please contact the
author.

Q9. How to create a VeraCrypt encrypted volume?
"""""""""""""""""""""""""""""""""""""""""""""""
This functionality is available from the command-line:

  $ ./tinyveracrypt.py init --type=veracrypt RAWDEVICE

tinyveracrypt also supports the `veracrypt --create' syntax, e.g. these are
equivalent:

  $ ./tinyveracrypt.py --text --create --quick --volume-type=normal --size=BYTESIZE --encryption=aes --hash=sha512 --filesystem=none --pim=0 --keyfiles= --random-source=/dev/urandom RAWDEVICE
  $ veracrypt          --text --create --quick --volume-type=normal --size=BYTESIZE --encryption=aes --hash=sha512 --filesystem=none --pim=0 --keyfiles= --random-source=/dev/urandom RAWDEVICE

Please note that `truecrypt' is not able to create a VeraCrypt encrypted
volume.

Q10. How to create TrueCrypt encrypted volume?
""""""""""""""""""""""""""""""""""""""""""""""
This functionality is available from the command-line:

  $ ./tinyveracrypt.py init --type=truecrypt RAWDEVICE

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
tinyveracrypt doesn't support LUKS2. See Q6 for more information.

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
It works only for TrueCrypt and VeraCrypt encrypted volumes. The command-line flag
is `tinyveracrypt.py init --ofs=0', but unfortunately some existing
tools won't be able to open the encrypted volume:

* For VeraCrypt encrypted volumes, `tinyveracrypt.py open' and `veracrypt
  --text --mount' are able to open them. `truecrypt' isn't able to open
  VeraCrypt encrypted volumes, and `cryptsetup open --type=tcrypt
  --veracrypt' in cryptsetup 1.7.3 has a bug (it doesn't decrease the
  decrypted volume size) and it fails with `Device ... is too small'.

  Unfortunately VeraCrypt 1.17 ignores --ofs=...
  (and also the encrypted volume size field in the header)
  if the raw device is smaller than 64 KiB.

* For TrueCrypt encrypted volumes, `tinyveracrypt.py open', `truecrypt
  --text --mount', and `veracrypt --text --mount --truecrypt' are able to open them.
  `cryptsetup open --type=tcrypt
  --veracrypt' in cryptsetup 1.7.3 has a bug (it doesn't decrease the
  decrypted volume size) and it fails with `Device ... is too small'.

  Unfortunately TrueCrypt 7.1a and VeraCrypt 1.17 ignore --ofs=...
  (and also the encrypted volume size field in the header)
  if the raw device is smaller than 64 KiB.

Don't do this unless you know the risks, and you are ready to lose
the VeraCrypt header (first 512 bytes of the raw device) if some tool
misbehaves.

If done carefully, this works with the following filesystems without data
loss: ext2, ext3, ext4, btrfs, reiserfs, jfs, nilfs, hfsplus, iso9660, udf,
minix and ocfs2, because they don't use the first 512 bytes of the volume.
Example:

  $ sudo ./tinyveracrypt.py init --type=veracrypt --ofs=0 --size=10M --filesystem=ext2 DEVICE.img

You can pass flags to mkfs.ext2 (e.g. -L) like this:

  $ sudo ./tinyveracrypt.py init --type=veracrypt --ofs=0 --size=10M --filesystem=ext2 -- -L MYLABEL -b 1024 DEVICE.img

tinyveracrypt has special code to make --ofs=0 work with FAT12 and FAT16
filesystems (but no FAT32 or NTFS). Use --filesystem=fat1:

  $ ./tinyveracrypt.py init --type=veracrypt --ofs=0 --size=10M --filesystem=fat1 DEVICE.img

Some other filesystems and data structures which don't work safely (because
they use the first 512 bytes of the raw device in their headers) include
vfat (FAT32 or without --filesystem=fat1), ntfs, xfs, exfat, Linux swap,
Linux RAID, LUKS.

Please note that cryptsetup 1.7.3 can't open such 0-overhead encrypted
volumes created with --ofs=0: it reports the error `Device ... is too
small.'. Use `tinyveracrypt' or `veracrypt' to open the encrypted volume.

Alternative, manual way to create the encrypted filesytem with --ofs=0:

  $ dd if=/dev/zero bs=1M count=10 of=DEVICE.img
  $ sudo ./tinyveracrypt.py open-table --keytable=random --ofs=0 --end-ofs=0 DEVICE.img NAME
  $ sudo mkfs.ext2 /dev/mapper/NAME
  $ #sudo mount /dev/mapper/NAME /media/NAMEDIR  # Optional.
  $ sudo ./tinyveracrypt.py init --type=veracrypt --opened --fake-luks-uuid=random /dev/mapper/NAME
  warning: abort now, otherwise the first 512 bytes of /dev/loop0 will be overwritten, destroying filesystems such as vfat, ntfs, xfs
  warning: abort now, otherwise encryption headers on /dev/loop0 will be replaced by a new veracrypt, old passphrases will be lost, encrypted data will be kept intact
  Enter passphrase:
  $ /sbin/blkid DEVICE.img
  DEVICE.img: UUID="1b564eef-2801-91f6-505c-cfd49044c8c0" TYPE="crypto_LUKS"

The advantage of --fake-luks-uuid=random is that /sbin/blkid is able to
detect the UUID above without opening the encrypted volume (i.e. without
knowing the passphrase).

The simple `tinyveracrypt.py init --type=veracrypt --ofs=0 --filesystem=...' commands above
also support `--fake-luks-uuid=...'.

The reason why mkfs was run before `tinyveracrypt.py init' is that mkfs
(including mkfs.ext2 and mkfs.minix) would otherwise overwrite the first 512
bytes, and we want to keep there the VeraCrypt header written by
tinyveracrypt.

`tinyveracrypt.py init --opened' does the correct block device buffer and
page table flushing no matter if the filesystem is mounted or not.

Q14. Can tinyveracrypt create and encrypted volume with plaintext volume
label and/or UUID, recognized by blkid?
"""""""""""""""""""""""""""""""""""""""
tinyveracrypt can create a VeraCrypt or TrueCrypt encrypted volume with a
fake LUKS header containing an unencrypted UUID (recognized by blkid in
util-linux and Busybox):

  $ ./tinyveracrypt.py init --type=veracrypt --fake-luks-uuid=random RAWDEVICE

The LUKS (LUKS1) headers don't contain a volume label field, so it's not
possible to specify one.

The created VeraCrypt encrypted volume will not be a valid LUKS volume
though, `cryptsetup open' won't be able to open it without the `--type
tcrypt --veracrypt' flag.

Alternatively, you can run

  $ ./tinyveracrypt.py init --type=veracrypt --mkfat=2K --fat-label=... --fat-uuid=... ... RAWDEVICE

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

  $ ./tinyveracrypt.py init --type=veracrypt --fake-luks-uuid=random RAWDEVICE

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

The recommended TrueCrypt version is 7.1a (released on 2012-02-07, archived
on https://truecrypt71a.com/). The latest release, 7.2 can also open
encrypted volumes, but it can't create new ones.

Alternatively, if you have cryptsetup >= 1.6.7 installed, run this:

  $ sudo cryptsetup         open --type tcrypt RAWDEVICE NAME

For compatibility, tinyveracrypt supports the same syntax:

  $ sudo ./tinyveracrypt.py open --type tcrypt RAWDEVICE NAME

The decrypted volume will be available as /dev/mapper/DEVNAME .

Please note that for VeraCrypt encrypted volumes you'd need to specify
`--veracrypt'.

Q23. Which command-line veracrypt and cryptsetup features are missing from
tinyveracrypt?
""""""""""""""
* creating and opening a hidden volume
* creating and opening a system volume
* booting from system volume
* reading the passpharse from a keyfile
* cipher other than those in Q4
* hash other than those in Q4
* volume type other than VeraCrypt, TrueCrypt and LUKS1 (e.g. LUKS2)
* mounting a filesystem at open time
* opening volumes on non-Linux systems (e.g. macOS or Windows)
* adding another passphrase (slot) to a LUKS volume after creation (this would
  be easy to add)
* verbose debug info similar to `cryptsetup --debug -v -v -v'
* volume diagnostics similar to `cryptsetup luksDump'

Q24. Can tinyveracrypt regenerate the volume header or convert between
VeraCrypt and TrueCrypt headers, or from LUKS?
""""""""""""""""""""""""""""""""""""""""""""""
Yes. To regenerate the TrueCrypt/VeraCrypt/LUKS header, open the encrypted
volume (as NAME), and then run:

  $ sudo ./tinyveracrypt.py init --type=veracrypt --opened --type=TYPE /dev/mapper/NAME

Pass flag `--type=truecrypt' to `init' if you want to generate a TrueCrypt
header or `--type=luks' if you want to generate a LUKS header. If needed,
pass any other flag (e.g. --mkfat=...), specify any passphrase.

Please note that the hidden volume, if any, will be destroyed as part of
this.

Quick header regeneration between VeraCrypt/TrueCrypt and LUKS usually
doesn't work, because the iv_offset values used by the cipher are different.
There is one exception: with --cipher=aes-lrw-benbi, quick header
regeneration between TrueCrypt and LUKS works. (VeraCrypt doesn't support
this cipher.)

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

The minimum size of the LUKS header (including the key material) is 4096,
checked by `cryptsetup open' in cryptsetup 1.7.3.

Q28B. What is the minimum size of a TrueCrypt or VeraCrypt encrypted volume?
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
The minimum size of the raw device is 1024 bytes, of which the header
occupies the first 512 bytes, and the encrypted data occupies the last 512
bytes. Both TrueCrypt 7.1a and VeraCrypt 1.17 can open such an encrypted
volume correctly. Create it like this:

  $ ./tinyveracrypt.py init --size=1024 --type=truecrypt mini.bin

(It also works with `--type=veracrypt'.)

512 bytes is too small for most filesystems, but you can create an encrypted
FAT12 filesystem with 512 bytes free in an encrypted raw device of 2560
bytes:

  $ ./tinyveracrypt.py init --size=2560 --filesystem=fat1 --type=truecrypt minifat12.bin

(It also works with `--type=veracrypt'.)

The sector layout of minifat.bin:

*    0... 512: TrueCrypt volume header.
*  512...1024: Encrypted FAT12 filesystem header (BPB) and boot sector.
* 1024...1536: Encrypted FAT12 file allocation table (FAT).
* 1536...2048: Encrypted FAT12 root directory, contains only the volume label.
* 2048...2560: Encrypted free space for a file up to 512 bytes.

By using the `tinyveracrypt.py init --ofs=0' trick explained in Q13 it's
possible to merge the first 2 sectors. Unfortunately it doesn't work
(`truecrypt' and `veracrypt' opens the encrypted device it with --ofs=512
instead) if the raw device is smaller than 64 KiB.

The smallest raw device size for which VeraCrypt 1.17 `veracrypt --text
--create' allows to create an encrypted volume (either TrueCrypt or
VeraCrypt) is 291 KiB.

The smallest raw device size for which TrueCrypt 7.1a `truecrypt --text
--create' allows to create a TrueCrypt encrypted volume is also 291 KiB.

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
  $ ./tinyveracrypt.py init --type=veracrypt --no-add-backup --no-truncate --size=10G DEVICE.img
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
tinyveracrypt has pure Python code embedded for all the ciphers, hashes and
other algorithms (e.g. PBKDF2 and key splitting to anti-forensic stripes).
See also Q4 for a full list of these algorithms.

tinyveracrypt use C extensions instead of the embedded Python code,
if available:

* ciphers: for AES-based ciphers, the base AES primitive is detected and
  used in pycrypto and in `aes'
* hashes: detected and used in hashlib (including hash implementation from
  OpenSSL) and pycrypto
* PBKDF2: detected and used in hashlib

FYI cryptsetup 1.7.3 can be compiled with any one of the supported crypto
backends such as the Linux kernel AF_ALG, gcrypt, Nettle, NSS, OpenSSL. For
the author of tinyveracrypt, the Linux kernel backend of cryptsetup didn't
work with kernel 3.13.0 (setsockopt returned EBUSY), kernel 2.6.35-32 (it
lacked AF_ALG altogether), and it worked with kernel 4.2.0.

Q33. What are the minimum Linux system requirements of the aes-xts-plain64
cipher?
"""""""
tinyveracrypt doesn't need Linux kernel support for encryption and hashing,
all the algorithms are embedded in its Python code. Linux kernel support is
needed for `tinyveracrypt.py open', because the corresponding `dmcrypt table'
command needs it. For these, tinyveracrypt needs Linux 2.6.33 (released
on 2010-02-24) or later and the dmsetup(8) command installed. Some ciphers
work with earlier kernels as well.

aes-xts-plain (an earlier variant which supports encrypted volumes up to 2
TiB) was introduced in Linux 2.6.24, aes-xts-plain64 was introduced in Linux
2.6.33. Please note that, like many Linux kernel features, the
aes-xts-plain64 cipher is optional: on certain distributions it may be
available as module, or not available at all.

Q34. How do I learn about the TrueCrypt on-disk format and the algorithm
TrueCrypt uses?
"""""""""""""""
Some resources:

* http://blog.bjrn.se/2008/01/truecrypt-explained.html : TrueCrypt 4.1, LRW.
  Includes functional Python code (which is compatible with truecrypt,
  cryptsetup and tinyveracrypt).
* http://blog.bjrn.se/2008/02/truecrypt-explained-truecrypt-5-update.html :
  TrueCrypt 5.0, XTS.
  Includes functional Python code (which is compatible with truecrypt,
  cryptsetup and tinyveracrypt).
* https://gitlab.com/cryptsetup/cryptsetup/wikis/TrueCryptOnDiskFormat :
  contains all encryption, hash, count etc. for TrueCrypt, but not for
  VeraCrypt.
* https://www.veracrypt.fr/en/VeraCrypt%20Volume%20Format%20Specification.html
* https://www.veracrypt.fr/en/Encryption%20Algorithms.html

Q35. What is the license of tinyveracrypt?
""""""""""""""""""""""""""""""""""""""""""
It is free software, GNU GPL >=2.0. There is NO WARRANTY. Use at your risk.

__END__
