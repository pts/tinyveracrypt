#! /usr/bin/python
# by pts@fazekas.hu at Sat Apr 13 17:47:01 CEST 2019

"""mkluks_demo.py: half-written alternative of `cryptsetup luksFormat'"""

import cStringIO
import itertools
import struct
import sys

import tinyveracrypt


def main(argv):
  # Command with similar output: /sbin/cryptsetup luksFormat --batch-mode --cipher=aes-xts-plain64 --hash=sha1 --use-urandom mkluks_demo.bin
  size = 2066432
  decrypted_ofs = 4096 # + 1024, for 8 key slots.
  key_size = 48 << 3
  keytable = ''.join(map(chr, xrange(3, 3 + (key_size >> 3))))
  header = tinyveracrypt.build_luks_header(
      passphrase=(tinyveracrypt.TEST_PASSPHRASE, 'abc'),
      #pim=-14,
      #hash='sha1',
      key_size=key_size,
      af_salt='xyzAB' * 4000,
      af_stripe_count=13,
      decrypted_ofs=decrypted_ofs,
      uuid='40bf7c9f-12a6-403f-81da-c4bd2183b74a',
      keytable_iterations=2, slot_iterations=3, # pim=-14,
      keytable=keytable,
      slot_salt=''.join(map(chr, xrange(6, 38))),
      keytable_salt=''.join(map(chr, xrange(32))),
      )
  header_padding = 'H' * (decrypted_ofs - len(header))
  payload0 = tinyveracrypt.crypt_aes_xts(keytable, 'Hello,_ ' * 64, do_encrypt=True, sector_idx=0)
  payload1 = tinyveracrypt.crypt_aes_xts(keytable, 'World!_ ' * 64, do_encrypt=True, sector_idx=1)
  payload2 = 'P' * (size - decrypted_ofs - len(payload0) - len(payload1))
  full_header = ''.join((header, header_padding, payload0, payload1, payload2))
  # Accepted by: ./mkluks_demo.py && /sbin/cryptsetup luksDump --debug mkluks_demo.bin
  open('mkluks_demo.bin', 'w+b').write(full_header)
  del full_header  # Save memory.
  sys.stdout.write(tinyveracrypt.build_table(keytable, size - decrypted_ofs, decrypted_ofs, '7:0', 0, 'aes-xts-plain64', True))
  decrypted_ofs2, keytable2, cipher = tinyveracrypt.get_open_luks_info(f=cStringIO.StringIO(''.join((header, header_padding, '\0' * 512))), passphrase='abc')
  assert cipher == 'aes-xts-plain64'
  assert (decrypted_ofs2, keytable2) == (decrypted_ofs, keytable), ((decrypted_ofs2, keytable2), (decrypted_ofs, keytable))


if __name__ == '__main__':
  sys.exit(main(sys.argv))
