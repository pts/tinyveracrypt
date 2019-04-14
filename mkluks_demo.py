#! /usr/bin/python
# by pts@fazekas.hu at Sat Apr 13 17:47:01 CEST 2019

"""mkluks_demo.py: half-written alternative of `cryptsetup luksFormat'"""

import struct
import sys


def main(argv):
  magic = 'LUKS\xba\xbe'
  version = 1
  cipher_name = 'aes'
  cipher_mode = 'xts-plain64'
  hash_spec = 'sha512'
  # In 512-byte sectors. Must be larger than key_material_offset, which is
  # at least 2, so payload_offset must be at least 3, thus the encrypted
  # LUKS1 payload is at least 1536 bytes smaller than the device, and the
  # minimum size for a LUKS1 device is 2048 bytes.
  payload_offset = 3
  key_bytes = 64
  mk_digest = 'D' * 20.
  mk_digest_salt = 'S' * 32.
  mk_digest_iter = 1000  # For PBKDF2.
  uuid = '40bf7c9f-12a6-403f-81da-c4bd2183b74a'
  active_tag = 0xac71f3
  inactive_tag = 0xdead
  iterations = 1000  # For PBKDF2.
  salt = 'T' * 32
  # If there is any invalid keyslot, then
  # `sudo /sbin/cryptsetup luksOpen mkluks_demo.bin foo --debug' will fail
  # without considering other keyslots.
  key_material_offset = 2  # Start sector of key material. >= 2.
  stripes = 1  # Number of anti-forensic stripes.
  key_slot1 = struct.pack(
      '>LL32sLL',
      active_tag, iterations, salt, key_material_offset, stripes)
  iterations = 0
  key_material_offset = 2
  stripes = 1
  inactive_key_slot = struct.pack(
      '>LL32xLL', inactive_tag, iterations, key_material_offset, stripes)
  key_material = 'M' * 512
  header = struct.pack(
      '>6sH32s32s32sLL20s32sL40s48s48s48s48s48s48s48s48s432x512s',
      magic, version, cipher_name, cipher_mode, hash_spec, payload_offset,
      key_bytes, mk_digest, mk_digest_salt, mk_digest_iter, uuid,
      key_slot1, inactive_key_slot, inactive_key_slot, inactive_key_slot,
      inactive_key_slot, inactive_key_slot, inactive_key_slot,
      inactive_key_slot, key_material)
  assert len(header) == 1536
  payload = 'P' * 512
  # Accepted by: ./mkluks_demo.py && /sbin/cryptsetup luksDump --debug mkluks_demo.bin
  # Keys are specified randomly though, see ``Figure 5: Pseudo code for
  # master key recovery'' in
  # http://clemens.endorphin.org/LUKS-on-disk-format.pdf on doing it properly.
  open('mkluks_demo.bin', 'r+b').write(header + payload)


if __name__ == '__main__':
  sys.exit(main(sys.argv))
