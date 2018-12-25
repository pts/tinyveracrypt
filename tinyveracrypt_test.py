#! /usr/bin/python

import tinyveracrypt

import sys

# Any 64 random bytes will do as a salt.
SALT = 'd97538ba99ca3182fd9e46184801a836a83a245f703247987dbd8d5c6a39ff5fbc4d03942ec54401d109d407c8033ede03930c95ddcc61b5b44ce3de6cac8b44'.decode('hex')
HEADER_KEY = '9e02d6ca37ac50a97093b3323545ec1cd9d11e03bfdaf123043bf1c42df5b6fc6660a2313e087fa80775942db79a9f297670f01ea6d555baa8599028cd8c8094'.decode('hex')


def test_crypt_aes_xts():
  crypt_aes_xts = tinyveracrypt.crypt_aes_xts
  decstr1, encstr1 = 'y' * 32, 'bb0ffec89c76220c0fa23c2f7a6ecfac1a98db623e5dab4517675d3d4206f05b'.decode('hex')
  decstr2, encstr2 = 'y' * 35, 'bb0ffec89c76220c0fa23c2f7a6ecfac304ee39a4a386ba1cd0135750d43c5331a98db'.decode('hex')
  decstr3, encstr3 = 'abcde' * 20, '08121025ff1c3e2bfa0d63310443c97441f9526dfe8339f191cdedce1b88380b9615c066c97e159f4d8c4cf8d143b30ad9b64120f4097352df44730a78c850ccd5733cc6409df94be7e2fc80b37eaa5718d372763c9f8d6795514010d1ba565b23e8b3b3'.decode('hex')
  decstr4, encstr4 = 'abcdef' * 5 + 'x', '900fb0b4eb5751d04f4141c59c1f4b0563dc58441d957bec7696f1a1a71ceb'.decode('hex')
  decstr5, encstr5 = 'abcdef' * 5 + 'x', '47523f8d4ff93e87495e6155b5bd3c74f8b97ce03b0c203172a99628995df1'.decode('hex')
  assert crypt_aes_xts(HEADER_KEY, '', True ) == ''
  assert crypt_aes_xts(HEADER_KEY, '', False) == ''
  assert crypt_aes_xts(HEADER_KEY, decstr1, True ) == encstr1
  assert crypt_aes_xts(HEADER_KEY, decstr1, False) != encstr1
  assert crypt_aes_xts(HEADER_KEY, encstr1, False) == decstr1
  assert crypt_aes_xts(HEADER_KEY, buffer(decstr2), True ) == encstr2
  assert crypt_aes_xts(HEADER_KEY, buffer(encstr2), False) == decstr2
  assert crypt_aes_xts(HEADER_KEY, decstr3, True ) == encstr3
  assert crypt_aes_xts(HEADER_KEY, encstr3, False) == decstr3
  assert crypt_aes_xts(HEADER_KEY, decstr3[32:], True , ofs=32) == encstr3[32:]
  assert crypt_aes_xts(HEADER_KEY, encstr3[48:], False, ofs=48) == decstr3[48:]
  assert crypt_aes_xts(HEADER_KEY, decstr4, True ) == encstr4
  assert crypt_aes_xts(HEADER_KEY, encstr4, False) == decstr4
  assert crypt_aes_xts(HEADER_KEY, decstr5, True , sector_idx=(1 << 70) - 42) == encstr5
  assert crypt_aes_xts(HEADER_KEY, encstr5, False, sector_idx=(1 << 70) - 42) == decstr5


def test():
  test_crypt_aes_xts()

  check_full_dechd = tinyveracrypt.check_full_dechd
  build_dechd = tinyveracrypt.build_dechd
  parse_dechd = tinyveracrypt.parse_dechd
  build_table = tinyveracrypt.build_table
  encrypt_header = tinyveracrypt.encrypt_header
  decrypt_header = tinyveracrypt.decrypt_header

  raw_device = '7:0'
  decrypted_size = 0x9000
  decrypted_ofs = 0x20000
  sector_size = 512
  # Any 64 random bytes will do as a keytable.
  keytable = 'a64cd0845765a19b0b5948f371f0b8c7b14da01677a10009d8b9199d511624233a54e1118dd6c9e2992e3ebae56081ca1f996c74c53f61f1a48f7fb17ddc6d5b'.decode('hex')
  enchd = SALT + '55ade210c4de6bbf5f623fb944908f0b4952958188dbe9ff0723cc6d6e1fdbf9554f4c9a0bbb4f49066641911ccbcb212234a9e677de9404d58950f5eceab3b9d2b290c071e4c74ee848af4ec2d730b13ded8d9bce64b92786b6eaa1c5abe23f23601a2f4ce30283c791f571548ef30b3b32c4558ec102a96176eea3864e3c3bd0f853e55df2de9125c4e782aca78479065839d7878122d9dc5ac8af8626218a3f74ca327a79b61d0cee6f8c4c5972bd53a87fdb7732a86f775e7f6c7ac801b79fa75759554dce512daa6bc4444b49907fa8adb7e5f14963aa8a6a8a3a5bf51b549a7d7569d641331749e88f453163a56a7a3c7f46375b3adfba9f30be9c41200dd9779eaf52220e732f3e4c7ee9c501e63ccd9c6f53bbb70f649c08d64eb740e034e26cdf8dd8209b2e8da9aac90dab3005215410c48109f263e50ba1fa736fd2de0b252bc008f2f1eab2e0fb42c5579bab32ac86686cc264181790c3426eb16dcbdea12f708758e19bbae1072ef7157cef87fd8722f2d2eca8a85510b83ea3d534031e38e018f8554944681885f7d912760d449bca4fbc39ff9bd2c2192f71550b131b2a2afe6371c7c122e6f5c865cb2cbbf889d2ce54da9f55a2000cf4e0'.decode('hex')
  dechd = SALT + ('564552410005010b5741849c0000000000000000000000000000000000000000000000000000000000009000000000000002000000000000000090000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b2df12c0' + keytable.encode('hex') + '00' * 192).decode('hex')

  assert len(SALT) == 64
  assert len(enchd) == 512
  assert len(dechd) == 512
  assert dechd.startswith(SALT)
  assert enchd.startswith(SALT)
  assert dechd[256 : 256 + 64] == keytable

  check_full_dechd(dechd)
  assert build_dechd(SALT, keytable, decrypted_size, sector_size) == dechd
  assert parse_dechd(dechd) == (keytable, decrypted_size, decrypted_ofs)
  table = build_table(keytable, decrypted_size, decrypted_ofs, raw_device)
  expected_table = '0 72 crypt aes-xts-plain64 a64cd0845765a19b0b5948f371f0b8c7b14da01677a10009d8b9199d511624233a54e1118dd6c9e2992e3ebae56081ca1f996c74c53f61f1a48f7fb17ddc6d5b 256 7:0 256 1 allow_discards\n'
  assert table == expected_table
  assert encrypt_header(dechd, HEADER_KEY) == enchd
  assert decrypt_header(enchd, HEADER_KEY) == dechd
  dechd2 = dechd[:-32] + '\1\1' + dechd[-30:]
  enchd2 = encrypt_header(dechd2, HEADER_KEY)
  i = 0
  while i < len(enchd) and enchd[:len(enchd) - i] != enchd2[: len(enchd) - i]:
    i += 1
  print 'CHANGED', i


def test_slow():
  print 'SLOW'
  sys.stdout.flush()
  passphrase = 'foo'
  assert build_header_key(passphrase, SALT) == HEADER_KEY  # Takes about 6..60 seconds.


if __name__ == '__main__':
  test()
  if len(sys.argv) > 1:
    test_slow()
  print __file__, ' OK.'
