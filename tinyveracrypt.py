#! /usr/bin/python
# by pts@fazekas.hu at Fri Oct 28 16:32:11 CEST 2016

import binascii
import struct


def check_decrypted_size(decrypted_size):
  min_decrypted_size = 36 << 10  # Enforced by VeraCrypt.
  if decrypted_size < min_decrypted_size:
    raise ValueError('decrypted_size must be at least %d bytes, got: %d' %
                     (min_decrypted_size, decrypted_size))
  if decrypted_size & 4095:
    raise ValueError('decrypted_size must be divisible by 4096, got: %d' %
                     decrypted_size)


def check_keytable(keytable):
  if len(keytable) != 64:
    raise ValueError('keytable must be 64 bytes, got: %d' % len(keytable))


def build_dechd(salt, keytable, decrypted_size, sector_size):
  check_keytable(keytable)
  check_decrypted_size(decrypted_size)
  if len(salt) != 64:
    raise ValueError('salt must be 64 bytes, got: %d' % len(salt))
  if sector_size < 512 or sector_size & (sector_size - 1):
    raise ValueError('sector_size must be a power of 2 at least 512: %d' % sector_size)
  version = 5
  keytablep = keytable + '\0' * 192
  keytablep_crc32 = ('%08x' % (binascii.crc32(keytablep) & 0xffffffff)).decode('hex')
  header_format_version = 5
  minimum_version_to_extract = (1, 11)
  hidden_volume_size = 0
  base_offset_for_key = 0x20000
  flag_bits = 0
  # 0 + 64: salt (not included in the header)
  # 64 + 4: "VERA": 56455241
  # 68 + 2: Volume header format version: 0005
  # 70 + 2: Minimum program version to open (1.11): 010b
  # 72 + 4: CRC-32 of the decrypted bytes 256..511: ????????
  # 76 + 16: zeros: 00000000000000000000000000000000
  # 92 + 8: size of hidden volume (0 for non-hidden): 0000000000000000
  # 100 + 8: size of decrypted volume: ????????????????
  # 108 + 8: byte offset of the master key scope (always 0x20000): 0000000000020000
  # 116 + 8: size of the encrypted area within the master key scope (same as size of the decrypted volume): ????????????????
  # 124 + 4: flag bits (0): 00000000
  # 128 + 4: sector size (512 -- shouldn't it be 4096?): 00000200
  # 132 + 120: zeros: 00..00
  header = struct.pack('>4sHBB4s16xQQQQLL120x', 'VERA', header_format_version, minimum_version_to_extract[0], minimum_version_to_extract[1], keytablep_crc32, hidden_volume_size, decrypted_size, base_offset_for_key, decrypted_size, flag_bits, sector_size)
  assert len(header) == 188
  header_crc32 = ('%08x' % (binascii.crc32(header) & 0xffffffff)).decode('hex')
  #assert 0, keytablep_crc32.encode('hex')
  dechd = ''.join((salt, header, header_crc32, keytablep))
  assert len(dechd) == 512
  return dechd


def build_table(keytable, decrypted_size, raw_device):
  check_keytable(keytable)
  check_decrypted_size(decrypted_size)
  if isinstance(raw_device, (list, tuple)):
    raw_device = '%d:%s' % tuple(raw_device)
  iv_offset = offset = 0x20000
  start_offset_on_logical = 0
  # https://www.kernel.org/doc/Documentation/device-mapper/dm-crypt.txt
  return '%d %d crypt aes-xts-plain64 %s %d %s %s 1 allow_discards\n' % (
      start_offset_on_logical,
      decrypted_size >> 9,
      keytable.encode('hex'),
      iv_offset >> 9,
      raw_device,
      offset >> 9)


def work():
  decrypted_size = 0x9000
  sector_size = 512
  salt = 'd97538ba99ca3182fd9e46184801a836a83a245f703247987dbd8d5c6a39ff5fbc4d03942ec54401d109d407c8033ede03930c95ddcc61b5b44ce3de6cac8b44'.decode('hex')
  keytable = 'a64cd0845765a19b0b5948f371f0b8c7b14da01677a10009d8b9199d511624233a54e1118dd6c9e2992e3ebae56081ca1f996c74c53f61f1a48f7fb17ddc6d5b'.decode('hex')
  enchd = salt + '55ade210c4de6bbf5f623fb944908f0b4952958188dbe9ff0723cc6d6e1fdbf9554f4c9a0bbb4f49066641911ccbcb212234a9e677de9404d58950f5eceab3b9d2b290c071e4c74ee848af4ec2d730b13ded8d9bce64b92786b6eaa1c5abe23f23601a2f4ce30283c791f571548ef30b3b32c4558ec102a96176eea3864e3c3bd0f853e55df2de9125c4e782aca78479065839d7878122d9dc5ac8af8626218a3f74ca327a79b61d0cee6f8c4c5972bd53a87fdb7732a86f775e7f6c7ac801b79fa75759554dce512daa6bc4444b49907fa8adb7e5f14963aa8a6a8a3a5bf51b549a7d7569d641331749e88f453163a56a7a3c7f46375b3adfba9f30be9c41200dd9779eaf52220e732f3e4c7ee9c501e63ccd9c6f53bbb70f649c08d64eb740e034e26cdf8dd8209b2e8da9aac90dab3005215410c48109f263e50ba1fa736fd2de0b252bc008f2f1eab2e0fb42c5579bab32ac86686cc264181790c3426eb16dcbdea12f708758e19bbae1072ef7157cef87fd8722f2d2eca8a85510b83ea3d534031e38e018f8554944681885f7d912760d449bca4fbc39ff9bd2c2192f71550b131b2a2afe6371c7c122e6f5c865cb2cbbf889d2ce54da9f55a2000cf4e0'.decode('hex')
  dechd = salt + '564552410005010b5741849c0000000000000000000000000000000000000000000000000000000000009000000000000002000000000000000090000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b2df12c0a64cd0845765a19b0b5948f371f0b8c7b14da01677a10009d8b9199d511624233a54e1118dd6c9e2992e3ebae56081ca1f996c74c53f61f1a48f7fb17ddc6d5b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'.decode('hex')

  assert len(salt) == 64
  assert len(enchd) == 512
  assert len(dechd) == 512
  assert dechd.startswith(salt)
  assert enchd.startswith(salt)
  assert dechd[256 : 256 + 64] == keytable
  #print 'calc  ', ('%08x' % (binascii.crc32(dechd[64 : 252]) & 0xffffffff)).decode('hex')[::-1].encode('hex')  # !! mismatch
  #print 'stored', dechd[252 : 256].encode('hex')
  assert ('%08x' % (binascii.crc32(dechd[256 : 512]) & 0xffffffff)).decode('hex') == dechd[72 : 76]
  assert ('%08x' % (binascii.crc32(dechd[64 : 252]) & 0xffffffff)).decode('hex') == dechd[252 : 256]

  dechd2 = build_dechd(salt, keytable, decrypted_size, sector_size)
  assert dechd2 == dechd
  table = build_table(keytable, decrypted_size, '7:0')
  expected_table = '0 72 crypt aes-xts-plain64 a64cd0845765a19b0b5948f371f0b8c7b14da01677a10009d8b9199d511624233a54e1118dd6c9e2992e3ebae56081ca1f996c74c53f61f1a48f7fb17ddc6d5b 256 7:0 256'

  print 'OK'


if __name__ == '__main__':
  work()
