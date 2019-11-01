#! /usr/bin/python

import tinyveracrypt

import sys

# Any 64 random bytes will do as a salt.
SALT = 'd97538ba99ca3182fd9e46184801a836a83a245f703247987dbd8d5c6a39ff5fbc4d03942ec54401d109d407c8033ede03930c95ddcc61b5b44ce3de6cac8b44'.decode('hex')
HEADER_KEY = '9e02d6ca37ac50a97093b3323545ec1cd9d11e03bfdaf123043bf1c42df5b6fc6660a2313e087fa80775942db79a9f297670f01ea6d555baa8599028cd8c8094'.decode('hex')


def benchmark_aes(new_aes):
  aes_obj = new_aes('Noob' * 8)  # AES-256.
  for _ in xrange(50000):
    assert aes_obj.encrypt('FooBarBa' * 2) == ';7\xa1\xf1V\xdc=\xad\xc2\xae\xe7\x02\xa6lg5'
    assert aes_obj.decrypt(';7\xa1\xf1V\xdc=\xad\xc2\xae\xe7\x02\xa6lg5') == 'FooBarBa' * 2


def benchmark_sha1():
  sha1 = tinyveracrypt.sha1
  for i in xrange(200):
    sha1_obj = sha1(str(i))
    for j in xrange(200):
      sha1_obj.update(i * str(j))
    sha1_obj.digest()


def test_aes():
  aes_obj = tinyveracrypt.new_aes('Noob' * 4)  # AES-128.
  assert aes_obj.encrypt('FooBarBa' * 2) == '9h\x82\xfd\x846\x0b\xb6(\x9a1\xe1~\x1ar\xcd'
  assert aes_obj.decrypt('9h\x82\xfd\x846\x0b\xb6(\x9a1\xe1~\x1ar\xcd') == 'FooBarBa' * 2

  aes_obj = tinyveracrypt.new_aes('Noob' * 6)  # AES-192.
  assert aes_obj.encrypt('FooBarBa' * 2) == '(\xfa\x90\xb4\xd2\x1e:\x84\xddw\xe4.\x19\x85\x1a\x93'
  assert aes_obj.decrypt('(\xfa\x90\xb4\xd2\x1e:\x84\xddw\xe4.\x19\x85\x1a\x93') == 'FooBarBa' * 2

  aes_obj = tinyveracrypt.new_aes('Noob' * 8)  # AES-256.
  assert aes_obj.encrypt('FooBarBa' * 2) == ';7\xa1\xf1V\xdc=\xad\xc2\xae\xe7\x02\xa6lg5'
  assert aes_obj.decrypt(';7\xa1\xf1V\xdc=\xad\xc2\xae\xe7\x02\xa6lg5') == 'FooBarBa' * 2


def test_sha512():
  assert tinyveracrypt.sha512('foobar').digest() == "\nP&\x1e\xbd\x1a9\x0f\xed+\xf3&\xf2g<\x14U\x82\xa64-R2\x04\x97=\x02\x193\x7f\x81aj\x80i\xb0\x12X|\xf5c_i%\xf1\xb5l6\x020\xc1\x9b'5\x00\xee\x01>\x03\x06\x01\xbf$%"
  assert tinyveracrypt.sha512('Foobar! ' * 14).digest() == 'H\x8c\x1f\x0f\x08\x1f\xce\x12\x1b\xe9q\x1cC)\xbe\xfa\xbd(\xbc+]\xf2T\xd6\xc9MS\x9c<&\x9c\xcf\xbb\x16<\x16\xfb\xc8\x19\xf9\xa8\xed\x19\x95f\xa9\xa1\xea\xc1x\xad\x19Txi\xe6\xbb*\xf3\x03\xb7k\xc02'
  d = tinyveracrypt.sha512('foobar')
  for i in xrange(200):
    d.update(buffer(str(i) * i))
  assert d.digest() == '\xc6\xd2\xec\x86\xfe\xaa\xff\xecJ\xc9w)\xfe\xe6\xff\xe5\\\x9fl\xc3~\xc2\x88\xdd\xb2G\xb0j\x8dM\xe2\xf6\xd5\xccv\xafY\xd57;T\xf0|m\xfeBGT\x90\xa0\xd4\xab\x060\xf5\x11!\xa3\xdbkV\x05\x98O'
  data = 'HelloWorld! ' * 20
  assert len(data) == 128 + 112  # On the % 128 < 112 boundary.
  assert tinyveracrypt.sha512(data).hexdigest() == 'bc15f07c1ab628c580128318a6349e242c0f6d2388f008709960f24bcd079f3229e4e7c07abf41649b8dc84b1439c36dfe848378422b24ac6a028f65b9de6049'
  assert tinyveracrypt.sha512(data[1:]).hexdigest() == '0b9e646aa4b3f8d8745c914eaf4fa10e7be6357043bc8504426c6d04971356e5bd068dbdb19d2e30061e49089d8ef0d97cc2ea1831a9c841507d234ba11d2f40'
  assert tinyveracrypt.sha512('?' + data).hexdigest() == 'fd4f94f3286d12bd00787bf071f14cabfe1f7d8af120b2e497e09e3203fc8e8f83d64b7a07fd9f516a85c464504c13cfed0d78fe6a5c90b726f9bb5a2cfc2f07'


def test_sha1():
  assert tinyveracrypt.sha1('foobar').digest() == '\x88C\xd7\xf9$\x16!\x1d\xe9\xeb\xb9c\xffL\xe2\x81%\x93(x'
  assert tinyveracrypt.sha1('Foobar! ' * 14).digest() == '\x14JM\x7f\xb2\xf6\xfc&\xc1\xfdG\x1c\xcc\xe5t%\xd3\x1b\x1c\\'
  d = tinyveracrypt.sha1('foobar')
  for i in xrange(200):
    d.update(buffer(str(i) * i))
  assert d.digest() == ".\xfc\x12Pm\xf1\x88\x81l\xd3\x15\xffZ\xcd'\xc8<\xa9M\xd4"
  data = 'HelloWorld! ' * 10
  assert len(data) == 64 + 56  # On the % 64 < 56 boundary.
  assert tinyveracrypt.sha1(data).hexdigest() == '256e19c0b3e3e17e2fa6c725f0300c4ecd7716df'
  assert tinyveracrypt.sha1(data[1:]).hexdigest() == '0e44b2fa9525d349ee2f40f4191a200100451c35'
  assert tinyveracrypt.sha1('?' + data).hexdigest(), 'cae6f1534687dfc3033fa9c494b5e6c80efa61ec'


def test_crypt_aes_xts():
  crypt_aes_xts = tinyveracrypt.crypt_aes_xts
  decstr1, encstr1 = 'y' * 32, 'bb0ffec89c76220c0fa23c2f7a6ecfac1a98db623e5dab4517675d3d4206f05b'.decode('hex')
  decstr2, encstr2 = 'y' * 35, 'bb0ffec89c76220c0fa23c2f7a6ecfac304ee39a4a386ba1cd0135750d43c5331a98db'.decode('hex')
  decstr3, encstr3 = 'abcde' * 20, '08121025ff1c3e2bfa0d63310443c97441f9526dfe8339f191cdedce1b88380b9615c066c97e159f4d8c4cf8d143b30ad9b64120f4097352df44730a78c850ccd5733cc6409df94be7e2fc80b37eaa5718d372763c9f8d6795514010d1ba565b23e8b3b3'.decode('hex')
  decstr4, encstr4 = 'abcdef' * 5 + 'x', '900fb0b4eb5751d04f4141c59c1f4b0563dc58441d957bec7696f1a1a71ceb'.decode('hex')
  decstr5, encstr5 = 'abcdef' * 5 + 'x', '034abcecdfb030eee19f00b7a570d28abe5a2dcc94010c9ff213e81d703a71'.decode('hex')
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
  decsec = 'Help!' * 206
  encsec = 'b4f90eebb6dc7660dd8ff234a5d3a5febb24ad850888a0b1dbc9c44e93f0a13d13fc1dd6600397183b48073aeb4924cde29529f43b18cf88407e11a467860a8a3266b7e70d09ebadd46687b402ff35b2556ea726059af9983d62da888ed398ac28e988094e402d21eb6eaee6255c3746e8925a371342d3c1fe9d024fdaa3a6357bdec9825663a01ff93909633b3ca94da7030427455aba1043dbe759bc166742786b28cc6ce0677fbe67fe9ef7d131059135adc3f2ea556886223297db189f969e0d8a3075ddd501a3ed8a95fbbdeb20cabfac2bcd3d1fad4e2bf92a6b34e503fa5c56d3099615a7c3912036a73ee611da8a3c8dd049fd70061a7d952af92f24760eb4777eb5be3fdd4a65f25e2c27960b06a32d2225ceb2619c196bd30c47f902bbb82aa9e3e7827fa1f0c81f8f20a47317d502a26dab7fcd2132e946a8e8558fef3b98d3f843add4a5eb426f5ed7b06a697bcc5f3b000774952bec58ebb8731c3737bf0932b2d0bb02a2c92b2baf882a4be5565259c23213c0817f9ca0e26484c7a07b431df6da75e8379e80727c1b9cca2b8fd9f7aa3566ad73838d440e3501f169cfbdb027ba1a32d9912c1636d68b0aa69236574e4379c0a2b84191464b4349372d6eed69aebbd84e7f9ed31da6e3aa139acfda20b9da54cde50de0bd7529267537b6113944d0ddd1a6ba7cef73926142ef084a8d497dad0d3832305bb293ec38acf8281a9f5dbc69786eb748e43b799933a77df7e21af6f190bb9c5635b7bc4010395f73d19b7fd4d314e2307ace30007bde66e05fcf7fc1002efcf9e30da6f10b1f296b2d873cd644e8c70cae987101f9e431242dcbb9e56c46ceb5310485e277e03ec8ab390e1268729d6d0b9d9cdf7aaa0c5f5dd8839c408530e26a98e74b5aa720de2e55e13870936c9e056ba7eb9fecd013055f6cf09fcc99d7255b0756e3fcaae233b589c53788eba48a095f8cfca20272c780a1af9d4cfe2ae78ed12ddc00547c2a98569ea76d346d3597dc9d5da316f4bc9b1e76799c1a62818393372b7159c1812ee90a05768c6f1d26efd6e90f07fb45b34cf5da4ab5f4281f873ad4c29180991a71d53413b781625e7dc7fcbaf54e879c171ffca87c3a9c8ef1b356a70f878350ea52e2bfc06c1e21db88a4702a67b7f1bd24bb39ada06e03e42cd34c20feb083c80d9d24ac52729f80614c52bea9da8691bcde98c8d7fcb8d92030dd470483f4bbdc3935251c4a9124e0becb2d3229f2bb1a2675a37e9208f633c583285c92f0dc7045326cb129560e3f9769f017515ef3a0194d97d9f84743ccb8c47acf51018b2a88b3359277bc4c54110b073e8dbb346e4a735db69ef110d0e98afe361e78c48bb0f29e21e1fe964e6227b1ce0992cced4d55b38071174bf6927efbd04ff9dbed6af1a208a720fb859bdfc5aa9479eacf27aeca87b73561567bef753d15874cbc852a5daefa'.decode('hex')
  assert tinyveracrypt.crypt_aes_xts_sectors(HEADER_KEY, decsec, True) == encsec
  assert tinyveracrypt.crypt_aes_xts_sectors(HEADER_KEY, encsec, False) == decsec + '\0' * (-len(decsec) & 15)


def test_veracrypt():
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
  table = build_table(keytable, decrypted_size, decrypted_ofs, raw_device, decrypted_ofs)
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


def test():
  test_aes()
  test_sha512()
  test_sha1()
  test_crypt_aes_xts()
  test_veracrypt()


def test_slow():
  print 'SLOW'
  sys.stdout.flush()
  passphrase = 'foo'
  # Runs PBKDIF2 with SHA-512 in 15000 iterations.
  # Takes about 6..60 seconds.
  assert tinyveracrypt.build_header_key(passphrase, SALT) == HEADER_KEY


if __name__ == '__main__':
  i = 1
  while i < len(sys.argv):
    arg = sys.argv[i]
    if arg == '--slow-aes':
      tinyveracrypt.new_aes = tinyveracrypt.SlowAes
    elif arg == '--slow-sha512':
      tinyveracrypt.sha512 = tinyveracrypt.SlowSha512
    elif arg == '--slow-sha1':
      tinyveracrypt.sha1 = tinyveracrypt.SlowSha1
    else:
      break
    i += 1
  if len(sys.argv) > i and sys.argv[i] == '--benchmark-slow-aes':
    benchmark_aes(new_aes=tinyveracrypt.SlowAes)
  elif len(sys.argv) > i and sys.argv[i] == '--benchmark-aes':
    benchmark_aes(new_aes=tinyveracrypt.new_aes)
  elif len(sys.argv) > i and sys.argv[i] == '--benchmark-sha1':
    benchmark_sha1()
  elif len(sys.argv) > i and sys.argv[i].startswith('-'):
    sys.exit('fatal: unknown flag: %s' % sys.argv[1])
  else:
    test()
    if len(sys.argv) > i:
      test_slow()
    print __file__, ' OK.'
