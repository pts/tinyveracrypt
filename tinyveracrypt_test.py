#! /usr/bin/python

import cStringIO
import sys

import tinyveracrypt

# Any 64 random bytes will do as a salt.
SALT = 'd97538ba99ca3182fd9e46184801a836a83a245f703247987dbd8d5c6a39ff5fbc4d03942ec54401d109d407c8033ede03930c95ddcc61b5b44ce3de6cac8b44'.decode('hex')
HEADER_KEY = '9e02d6ca37ac50a97093b3323545ec1cd9d11e03bfdaf123043bf1c42df5b6fc6660a2313e087fa80775942db79a9f297670f01ea6d555baa8599028cd8c8094'.decode('hex')
DECSTR = '0123456789abcdefHelloHelloHello,WorldWorldWorld\n'


def crypt_sectors(cipher, keytable, data, do_encrypt, sector_idx=0, ofs=0):
  yield_crypt_sectors_func, get_codebooks_func = tinyveracrypt.get_crypt_sectors_funcs(cipher, len(keytable))
  codebooks = get_codebooks_func(keytable)
  if ofs:
    return ''.join(yield_crypt_sectors_func(codebooks, data, do_encrypt, sector_idx, ofs=ofs))
  else:
    return ''.join(yield_crypt_sectors_func(codebooks, data, do_encrypt, sector_idx))


def test_crc32():
  crc32 = tinyveracrypt.crc32
  assert crc32('') == 0
  assert crc32('Hello, World!') == -330644528
  assert crc32('Hello, Worl!') == 552416217
  assert crc32('Hello, Wor!') == -2051987617
  assert crc32('Hello, Wo!') == 689960731
  assert crc32(buffer('Hello, Wo!')) == 689960731


def benchmark_aes(new_aes):
  aes_obj = new_aes('Noob' * 8)  # AES-256.
  for _ in xrange(50000):
    assert aes_obj.encrypt('FooBarBa' * 2) == ';7\xa1\xf1V\xdc=\xad\xc2\xae\xe7\x02\xa6lg5'
    assert aes_obj.decrypt(';7\xa1\xf1V\xdc=\xad\xc2\xae\xe7\x02\xa6lg5') == 'FooBarBa' * 2


def test_aes():
  aes_obj = tinyveracrypt.new_aes('Noob' * 4)  # AES-128, 16-byte key.
  assert aes_obj.encrypt('FooBarBa' * 2) == '9h\x82\xfd\x846\x0b\xb6(\x9a1\xe1~\x1ar\xcd'
  assert aes_obj.decrypt('9h\x82\xfd\x846\x0b\xb6(\x9a1\xe1~\x1ar\xcd') == 'FooBarBa' * 2

  aes_obj = tinyveracrypt.new_aes('Noob' * 6)  # AES-192, 24-byte key.
  assert aes_obj.encrypt('FooBarBa' * 2) == '(\xfa\x90\xb4\xd2\x1e:\x84\xddw\xe4.\x19\x85\x1a\x93'
  assert aes_obj.decrypt('(\xfa\x90\xb4\xd2\x1e:\x84\xddw\xe4.\x19\x85\x1a\x93') == 'FooBarBa' * 2

  aes_obj = tinyveracrypt.new_aes('Noob' * 8)  # AES-256, 32-byte key.
  assert aes_obj.encrypt('FooBarBa' * 2) == ';7\xa1\xf1V\xdc=\xad\xc2\xae\xe7\x02\xa6lg5'
  assert aes_obj.decrypt(';7\xa1\xf1V\xdc=\xad\xc2\xae\xe7\x02\xa6lg5') == 'FooBarBa' * 2


def test_sha512():
  sha512 = tinyveracrypt.HASH_DIGEST_PARAMS['sha512'][0]
  assert sha512('foobar').digest() == "\nP&\x1e\xbd\x1a9\x0f\xed+\xf3&\xf2g<\x14U\x82\xa64-R2\x04\x97=\x02\x193\x7f\x81aj\x80i\xb0\x12X|\xf5c_i%\xf1\xb5l6\x020\xc1\x9b'5\x00\xee\x01>\x03\x06\x01\xbf$%"
  assert sha512('Foobar! ' * 14).digest() == 'H\x8c\x1f\x0f\x08\x1f\xce\x12\x1b\xe9q\x1cC)\xbe\xfa\xbd(\xbc+]\xf2T\xd6\xc9MS\x9c<&\x9c\xcf\xbb\x16<\x16\xfb\xc8\x19\xf9\xa8\xed\x19\x95f\xa9\xa1\xea\xc1x\xad\x19Txi\xe6\xbb*\xf3\x03\xb7k\xc02'
  d = sha512('foobar')
  for i in xrange(200):
    d.update(buffer(str(i) * i))
  assert d.digest() == '\xc6\xd2\xec\x86\xfe\xaa\xff\xecJ\xc9w)\xfe\xe6\xff\xe5\\\x9fl\xc3~\xc2\x88\xdd\xb2G\xb0j\x8dM\xe2\xf6\xd5\xccv\xafY\xd57;T\xf0|m\xfeBGT\x90\xa0\xd4\xab\x060\xf5\x11!\xa3\xdbkV\x05\x98O'
  data = 'HelloWorld! ' * 20
  assert len(data) == 128 + 112  # On the % 128 < 112 boundary.
  assert sha512(data).hexdigest() == 'bc15f07c1ab628c580128318a6349e242c0f6d2388f008709960f24bcd079f3229e4e7c07abf41649b8dc84b1439c36dfe848378422b24ac6a028f65b9de6049'
  assert sha512(data[1:]).hexdigest() == '0b9e646aa4b3f8d8745c914eaf4fa10e7be6357043bc8504426c6d04971356e5bd068dbdb19d2e30061e49089d8ef0d97cc2ea1831a9c841507d234ba11d2f40'
  assert sha512('?' + data).hexdigest() == 'fd4f94f3286d12bd00787bf071f14cabfe1f7d8af120b2e497e09e3203fc8e8f83d64b7a07fd9f516a85c464504c13cfed0d78fe6a5c90b726f9bb5a2cfc2f07'


def test_sha384():
  sha384 = tinyveracrypt.HASH_DIGEST_PARAMS['sha384'][0]
  assert sha384('foobar').digest() == '<\x9c0\xd9\xf6e\xe7MQ\\\x84)`\xd4\xa4Q\xc8:\x01%\xfd=\xe79-{7#\x1a\xf1\x0cr\xeaX\xae\xdf\xcd\xf8\x9aWe\xbf\x90*\xf9>\xcf\x06'
  assert sha384('Foobar! ' * 14).digest() == '\x99\x93.\xcf\x93Rd\xa9\x8f4\xe2\x90\x13\xdf\xe2\xd7@\xd0\x85\x85\xd1"\xfa\xde\xfb\x1c\x16x"\x8b\xbc}\x01\xc0\x84\xe6\xf4\xacs\xea;\xe5\xb49{\xcc\xc9='
  d = sha384('foobar')
  for i in xrange(200):
    d.update(buffer(str(i) * i))
  assert d.digest() == "\n\xe3b\xb3\xde\xe4&6\xcc\xa5\xb2\xe1\x9c\x0c\xce)\xbaQ\xee\x03\xa3\xfb`\xac\xbe\xc6#X\x8c\xe4\xfc\xb8\xdf\xbeA\x9f+\x8e%\x80-'7=\xc0*J\xa1"
  data = 'HelloWorld! ' * 20
  assert len(data) == 128 + 112  # On the % 128 < 112 boundary.
  assert sha384(data).hexdigest() == '736a462a4e4bca1d8e831b264916ba8dd6e55e0b969389191f7b9bf98b0acd022678c07831d58e74b3cc27d9386f4410'
  assert sha384(data[1:]).hexdigest() == 'fce5bf3c6c810b45c8b60ab20d840fab178d01e919e48641345ca4de4784a581345b0e0bf605da94b1ab7d222c8aef22'
  assert sha384('?' + data).hexdigest() == '921d38ed1012801b42b1ffacc08940782c1d67a06ff72f3d6eb89d9982f6a4b4f6bebb6effbba17333c9c738952b6f0d'


def test_sha256():
  sha256 = tinyveracrypt.HASH_DIGEST_PARAMS['sha256'][0]
  assert sha256('foobar').digest() == '\xc3\xab\x8f\xf17 \xe8\xad\x90G\xdd9Fk<\x89t\xe5\x92\xc2\xfa8=J9`qL\xae\xf0\xc4\xf2'
  assert sha256('Foobar! ' * 14).digest() == '-?\xe9\x86\xb6\x1f\x1b\xbb\xa2\xbf\x83\xb7\xcd<\xd1\xe9MR]~8\x8e\xdf3\x911u"\xfb\x0c/{'
  d = sha256('foobar')
  for i in xrange(200):
    d.update(buffer(str(i) * i))
  assert d.digest() == '\xec\x11\xa7\xff^\xa3\x8a\x04O\xe3\x93\xf5i\x94\x11+m\x8b\x11\x92\x8895E\x19\xe7\xa2\xb9]\xf3\xf5X'
  data = 'HelloWorld! ' * 10
  assert len(data) == 64 + 56  # On the % 64 < 56 boundary.
  assert sha256(data).hexdigest() == 'f890457a817af29473f5057f1a80ac71fda6b0c4895a6fbfc9a63cd77abe15be'
  assert sha256(data[1:]).hexdigest() == '42f53c9828d7033fe258d68286ec47999dd67129d18d50d340b736e7a6222920'
  assert sha256('?' + data).hexdigest() == 'caa9d54ee0700e483d1dcfb19cbcc4eafc5bbb7913492fbdbea63835346bc172'


def test_sha224():
  sha224 = tinyveracrypt.HASH_DIGEST_PARAMS['sha224'][0]
  assert sha224('foobar').digest() == '\xdev\xc3\xe5g\xfc\xa9\xd2F\xf5\xf8\xd3\xb2\xe7\x04\xa3\x8c<^%\x89\x88\xabR_\x94\x1d\xb8'
  assert sha224('Foobar! ' * 14).digest() == 'MD\xdf\x8e\r\xf8\xe5\xc1\xa2\xc5\xff5E1\xc6%?\xe2\xa48h\x80\xec\xf37\x90\xc1\xee'
  d = sha224('foobar')
  for i in xrange(200):
    d.update(buffer(str(i) * i))
  assert d.digest() == 'x\xcc|r\x18y-\x02\xf9\xfc\xf3\xd5\x13\xcc\xaaid\x02s\xf0\xb1\xf5\xdcyR\xda\xb8\xf5'
  data = 'HelloWorld! ' * 10
  assert len(data) == 64 + 56  # On the % 64 < 56 boundary.
  assert sha224(data).hexdigest() == 'a9d4b422a0c5dc502a305ce6d523b3690cddc5a6632692e749d6eebf'
  assert sha224(data[1:]).hexdigest() == '543aa2d1cb3de1289eb0714198d9817d22c9b2e937a633feb8120d76'
  assert sha224('?' + data).hexdigest() == '4963373611b0de1e9a0533deb1aecdbfccae74d1ae6ae6515e7c2812'


def test_ripemd160():
  ripemd160 = tinyveracrypt.HASH_DIGEST_PARAMS['ripemd160'][0]
  assert ripemd160('foobar').digest() == '\xa0n2~\xa78\x8c\x18\xe4t\x0e5\x0e\xd4\xe6\x0f.\x04\xfcA'
  assert ripemd160('Foobar! ' * 14).digest() == '\xf6\x17IT~\xd3sDA\x01\x8e_<\x80Lf\x8e\xc2\x17{'
  d = ripemd160('foobar')
  for i in xrange(200):
    d.update(buffer(str(i) * i))
  assert d.digest() == '\x8d\x03p\x88\x88\xd3y\xd4\x0bIt\t\xda}\xf10a\x11\x16f'
  data = 'HelloWorld! ' * 10
  assert len(data) == 64 + 56  # On the % 64 < 56 boundary.
  assert ripemd160(data).hexdigest() == '87dc601d75eb635180abe2f0c4c7649c2602530e'
  assert ripemd160(data[1:]).hexdigest() == '5af0370161749037b942aea0b19eb3bf58e151b2'
  assert ripemd160('?' + data).hexdigest() == '43856e8669a5360fc6bb4140ddee5710a8cf2c27'


def test_whirlpool():
  whirlpool = tinyveracrypt.HASH_DIGEST_PARAMS['whirlpool'][0]
  assert whirlpool('foobar').digest() == '\x99#\xaf\xae\xc3\xa8o\x86[\xb21\xa5\x88\xf4S\xf8N\x81Q\xa2\xde\xb4\x10\x9a\xeb\xc6\xdeB\x84\xbe[\xeb\xcf\xf4\xfa\xb8*~Q\xd9 #s@\xa0Csn\x9d\x13\xba\xb1\x96\x00m\xcc\xa0\xfee1Mh\xea\xb9'
  assert whirlpool('Foobar! ' * 14).digest() == '\x8dL\x84ch\xe5\xb0\xda\xc1\xa9] %\x8e]~\x84\x14\x02\xd42\x92b\xc5~6\x92\xfa\x83\\vj\xdf\x90\xe5\xe0u\xdd1\xcbzu?n\xf3\x02n\xd6\xb8\xe13?\xf9\xfcL\xd2\xf8T\xafP\xae\xf7B\xc7'
  assert whirlpool('').hexdigest() == '19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3'
  assert whirlpool('This is the horse and the hound and the horn\nThat belonged to the farmer sowing his corn\nThat kept the rooster that crowed in the morn\nThat woke the judge all shaven and shorn\n').hexdigest() == (
      '5947a4bc358d845677ebcd428e27f143bd717cc96afa13cb3d16f7951d4602b4854d94da454faba7e7be9af97577dd8029f9efcd0cdcce7f5e0c13588948da04')
  assert whirlpool('The quick brown fox jumps over the lazy dog').hexdigest() == 'b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35'
  assert whirlpool('The quick brown fox jumps over the lazy eog').hexdigest() == 'c27ba124205f72e6847f3e19834f925cc666d0974167af915bb462420ed40cc50900d85a1f923219d832357750492d5c143011a76988344c2635e69d06f2d38c'
  w = whirlpool('This is the message to be hashe: the quick brown fox jumps over the lazy ')
  w2 = w.copy()
  w2.update('dog')
  assert w2.hexdigest() == '9c64fe18efcc7751531ce411a064afe82ba4b2ecd6bb410a355647c151cd59fb1043a752d7ed8ad55a47975ad0f429ff4c08360c87a308784dee27e52ce7b7cd'
  assert w2.hexdigest() == '9c64fe18efcc7751531ce411a064afe82ba4b2ecd6bb410a355647c151cd59fb1043a752d7ed8ad55a47975ad0f429ff4c08360c87a308784dee27e52ce7b7cd'  # Idempotent.
  assert w.hexdigest() != w2.hexdigest()
  w.update('dog')
  assert w.hexdigest() == w2.hexdigest()
  assert whirlpool('The quick brown fox jumps over t').hexdigest() == (
      '4a5755d85135ce0b7f89894f4ed8b79e15a4a0cd35e11dbfcdf6b656ba658adc5aaae0dc54bc3faa318c62ba03dc9ddaf4d0e1a6554005232256ebc2a22faa5c')
  assert whirlpool('The quick brown fox jumps over the lazy dog. The quick brown fox').hexdigest() == '0cd7fd6a0a2effbcff809b2de658adf34c3a3af2c20576816c9599ba1fd47cfc27b7639b7ba16de3889c280038ee1813cb100bf4013e5df1bb5d149327db8a3b'
  d = whirlpool('foobar')
  for i in xrange(200):
    d.update(buffer(str(i) * i))
  assert d.digest() == '\x83\x08\x1b9\x83X\xb7\x8e9R%\x8b\xbb\xfa\nX\xa14A\x94\x9cR(\x1a\x18D!\x98_\xc5gUu\x96\xa9\xa8C\x11cP\x91\xbf\xdaI"Af>\x1e&\'\x997\xccc7\xd1)\x81\x03|\x90\xb06'
  data = 'HelloWorld! ' * 8
  assert len(data) == 64 + 32  # On the % 64 < 32 boundary.
  assert whirlpool(data).hexdigest() == 'ad570e544e9ac2ecdd2e32ea62911029ede9a9d85b6d374dfdc02152576438394668de3b154b9f4402dd7332307abdbca515a907cab1ad4d0fb314fce643f727'
  assert whirlpool(data[1:]).hexdigest() == '3b3fccfeec86ea76d4b2e6008c10514fb03d84478e4bcfce2228b6a462e4d296a657286b7f64ec8de488880bf7b76138686f13021eb237987e08e92e722efdce'
  assert whirlpool('?' + data).hexdigest() == '5a743e13b415087036275eb798fcf0770b707bc9a416a0c8829c4192396742e3434fd57ccb10602a0ffdbff3ff009e34ab52f1184dcf508fca0b984a912cf437'


def test_md5():
  md5 = tinyveracrypt.HASH_DIGEST_PARAMS['md5'][0]
  assert md5('foobar').digest() == '8X\xf6"0\xac<\x91_0\x0cfC\x12\xc6?'
  assert md5('Foobar! ' * 14).digest() == 'ht\xd1\xb6pq#P\xc3\x8eI\x83\x83`\xff\xb4'
  d = md5('foobar')
  for i in xrange(200):
    d.update(buffer(str(i) * i))
  assert d.digest() == '\x91\x92q\xba\xd1uiq\\\x82\xddN\xeaqR\xe2'
  data = 'HelloWorl' * 7 + 'd'
  data = 'HelloWorld! ' * 10
  assert len(data) == 64 + 56  # On the % 64 < 56 boundary.
  assert md5(data).hexdigest() == 'f1f0fff69d07c75d8d0720178a8eaa41'
  assert md5(data[1:]).hexdigest() == '2bd7dde9dbf3c1a8171458e3ddf11ed1'
  assert md5('?' + data).hexdigest() == '50e0dc0736bbb3f38acfeee7432f76c2'


def benchmark_sha1():
  sha1 = tinyveracrypt.sha1
  for i in xrange(200):
    sha1_obj = sha1(str(i))
    for j in xrange(200):
      sha1_obj.update(i * str(j))
    sha1_obj.digest()


def test_sha1():
  sha1 = tinyveracrypt.HASH_DIGEST_PARAMS['sha1'][0]
  assert sha1('foobar').digest() == '\x88C\xd7\xf9$\x16!\x1d\xe9\xeb\xb9c\xffL\xe2\x81%\x93(x'
  assert sha1('Foobar! ' * 14).digest() == '\x14JM\x7f\xb2\xf6\xfc&\xc1\xfdG\x1c\xcc\xe5t%\xd3\x1b\x1c\\'
  d = sha1('foobar')
  for i in xrange(200):
    d.update(buffer(str(i) * i))
  assert d.digest() == ".\xfc\x12Pm\xf1\x88\x81l\xd3\x15\xffZ\xcd'\xc8<\xa9M\xd4"
  data = 'HelloWorld! ' * 10
  assert len(data) == 64 + 56  # On the % 64 < 56 boundary.
  assert sha1(data).hexdigest() == '256e19c0b3e3e17e2fa6c725f0300c4ecd7716df'
  assert sha1(data[1:]).hexdigest() == '0e44b2fa9525d349ee2f40f4191a200100451c35'
  assert sha1('?' + data).hexdigest(), 'cae6f1534687dfc3033fa9c494b5e6c80efa61ec'


def help_test_crypt_sectors(cipher_prefix, key, test_vectors):
  encstr92, encstr93, encstr94, encstr95 = test_vectors
  p = cipher_prefix
  decstr = DECSTR
  if 0 and cipher_prefix == 'aes-lrw-':
    print crypt_sectors(p + 'essiv:sha256', key, decstr, True, sector_idx=333).encode('hex')
    print crypt_sectors(p + 'plain64', key, decstr, True, sector_idx=333).encode('hex')
    print crypt_sectors(p + 'plain64be', key, decstr, True, sector_idx=333).encode('hex')
    print crypt_sectors(p + 'plain64', key, decstr, True, sector_idx=0x98765123456789ab).encode('hex')
  assert crypt_sectors(p + 'essiv:sha256', key, decstr, True, sector_idx=333) == encstr92
  assert crypt_sectors(p + 'essiv:sha256', key, encstr92, False, sector_idx=333) == decstr
  assert crypt_sectors(p + 'essiv:sha256', key, decstr, True, sector_idx=334) != encstr92
  assert crypt_sectors(p + 'essiv:sha256', key, decstr[:32], True, sector_idx=333) == encstr92[:32]
  assert crypt_sectors(p + 'essiv:sha256', key, encstr92[:32], False, sector_idx=333) == decstr[:32]
  assert crypt_sectors(p + 'plain64', key, decstr, True, sector_idx=333) == encstr93
  assert crypt_sectors(p + 'plain64', key, encstr93, False, sector_idx=333) == decstr
  assert crypt_sectors(p + 'plain64', key, decstr, True, sector_idx=334) != encstr93
  assert crypt_sectors(p + 'plain64', key, decstr[:32], True, sector_idx=333) == encstr93[:32]
  assert crypt_sectors(p + 'plain64', key, encstr93[:32], False, sector_idx=333) == decstr[:32]
  assert crypt_sectors(p + 'plain64', key, decstr, True, sector_idx=333 | 1 << 64) == encstr93
  assert crypt_sectors(p + 'plain64', key, decstr, True, sector_idx=0x98765123456789ab) == encstr95
  assert crypt_sectors(p + 'plain64', key, encstr95, False, sector_idx=0x98765123456789ab) == decstr
  assert crypt_sectors(p + 'plain', key, decstr, True, sector_idx=333) == encstr93
  assert crypt_sectors(p + 'plain', key, encstr93, False, sector_idx=333) == decstr
  assert crypt_sectors(p + 'plain', key, decstr, True, sector_idx=334) != encstr93
  assert crypt_sectors(p + 'plain', key, decstr[:32], True, sector_idx=333) == encstr93[:32]
  assert crypt_sectors(p + 'plain', key, encstr93[:32], False, sector_idx=333) == decstr[:32]
  assert crypt_sectors(p + 'plain', key, encstr93, False, sector_idx=333 | 1 << 32) == decstr
  assert crypt_sectors(p + 'plain', key, decstr, True, sector_idx=0x00ffffffff) == crypt_sectors(p + 'plain64', key, decstr, True, sector_idx=0x00ffffffff)
  assert crypt_sectors(p + 'plain', key, decstr, True, sector_idx=0x0100000000) != crypt_sectors(p + 'plain64', key, decstr, True, sector_idx=0x0100000000)
  assert crypt_sectors(p + 'plain64be', key, decstr, True, sector_idx=333) == encstr94
  assert crypt_sectors(p + 'plain64be', key, encstr94, False, sector_idx=333) == decstr
  assert crypt_sectors(p + 'plain64be', key, decstr, True, sector_idx=334) != encstr94
  assert crypt_sectors(p + 'plain64be', key, decstr[:32], True, sector_idx=333) == encstr94[:32]
  assert crypt_sectors(p + 'plain64be', key, encstr94[:32], False, sector_idx=333) == decstr[:32]


def test_crypt_aes_xts():
  crypt_aes_xts = tinyveracrypt.crypt_aes_xts
  decstr1, encstr1 = 'y' * 32, 'bb0ffec89c76220c0fa23c2f7a6ecfac1a98db623e5dab4517675d3d4206f05b'.decode('hex')
  decstr2, encstr2 = 'y' * 35, 'bb0ffec89c76220c0fa23c2f7a6ecfac304ee39a4a386ba1cd0135750d43c5331a98db'.decode('hex')
  decstr3, encstr3 = 'abcde' * 20, '08121025ff1c3e2bfa0d63310443c97441f9526dfe8339f191cdedce1b88380b9615c066c97e159f4d8c4cf8d143b30ad9b64120f4097352df44730a78c850ccd5733cc6409df94be7e2fc80b37eaa5718d372763c9f8d6795514010d1ba565b23e8b3b3'.decode('hex')
  decstr4, encstr4 = 'abcdef' * 5 + 'x', '900fb0b4eb5751d04f4141c59c1f4b0563dc58441d957bec7696f1a1a71ceb'.decode('hex')
  decstr5, encstr5 = 'abcdef' * 5 + 'x', '034abcecdfb030eee19f00b7a570d28abe5a2dcc94010c9ff213e81d703a71'.decode('hex')
  decstr6, encstr6 = 'abcdef' * 5 + 'x', 'baaafe2c516df093cc3845fa541829b48ed951cb918a0de12803748e8b596b'.decode('hex')
  decstr7, encstr7 = 'abcdef' * 5 + 'x', '4fe1e375a8bddece494d188f9005e5d0ad1b378c7ef25ce38b941aba2bdd06'.decode('hex')
  decstr9, encstr9 = 'Help!' * 206 + 10 * '\0', 'b4f90eebb6dc7660dd8ff234a5d3a5febb24ad850888a0b1dbc9c44e93f0a13d13fc1dd6600397183b48073aeb4924cde29529f43b18cf88407e11a467860a8a3266b7e70d09ebadd46687b402ff35b2556ea726059af9983d62da888ed398ac28e988094e402d21eb6eaee6255c3746e8925a371342d3c1fe9d024fdaa3a6357bdec9825663a01ff93909633b3ca94da7030427455aba1043dbe759bc166742786b28cc6ce0677fbe67fe9ef7d131059135adc3f2ea556886223297db189f969e0d8a3075ddd501a3ed8a95fbbdeb20cabfac2bcd3d1fad4e2bf92a6b34e503fa5c56d3099615a7c3912036a73ee611da8a3c8dd049fd70061a7d952af92f24760eb4777eb5be3fdd4a65f25e2c27960b06a32d2225ceb2619c196bd30c47f902bbb82aa9e3e7827fa1f0c81f8f20a47317d502a26dab7fcd2132e946a8e8558fef3b98d3f843add4a5eb426f5ed7b06a697bcc5f3b000774952bec58ebb8731c3737bf0932b2d0bb02a2c92b2baf882a4be5565259c23213c0817f9ca0e26484c7a07b431df6da75e8379e80727c1b9cca2b8fd9f7aa3566ad73838d440e3501f169cfbdb027ba1a32d9912c1636d68b0aa69236574e4379c0a2b84191464b4349372d6eed69aebbd84e7f9ed31da6e3aa139acfda20b9da54cde50de0bd7529267537b6113944d0ddd1a6ba7cef73926142ef084a8d497dad0d3832305bb293ec38acf8281a9f5dbc69786eb748e43b799933a77df7e21af6f190bb9c5635b7bc4010395f73d19b7fd4d314e2307ace30007bde66e05fcf7fc1002efcf9e30da6f10b1f296b2d873cd644e8c70cae987101f9e431242dcbb9e56c46ceb5310485e277e03ec8ab390e1268729d6d0b9d9cdf7aaa0c5f5dd8839c408530e26a98e74b5aa720de2e55e13870936c9e056ba7eb9fecd013055f6cf09fcc99d7255b0756e3fcaae233b589c53788eba48a095f8cfca20272c780a1af9d4cfe2ae78ed12ddc00547c2a98569ea76d346d3597dc9d5da316f4bc9b1e76799c1a62818393372b7159c1812ee90a05768c6f1d26efd6e90f07fb45b34cf5da4ab5f4281f873ad4c29180991a71d53413b781625e7dc7fcbaf54e879c171ffca87c3a9c8ef1b356a70f878350ea52e2bfc06c1e21db88a4702a67b7f1bd24bb39ada06e03e42cd34c20feb083c80d9d24ac52729f80614c52bea9da8691bcde98c8d7fcb8d92030dd470483f4bbdc3935251c4a9124e0becb2d3229f2bb1a2675a37e9208f633c583285c92f0dc7045326cb129560e3f9769f017515ef3a0194d97d9f84743ccb8c47acf51018b2a88b3359277bc4c54110b073e8dbb346e4a735db69ef110d0e98afe361e78c48bb0f29e21e1fe964e6227b1ce0992cced4d55b38071174bf6927efbd04ff9dbed6af1a208a720fb859bdfc5aa9479eacf27aeca87b73561567bef753d15874cbc852a5daefa'.decode('hex')
  assert len(HEADER_KEY) == 64
  assert crypt_aes_xts(HEADER_KEY, '', True ) == ''
  assert crypt_aes_xts(HEADER_KEY, '', False) == ''
  assert crypt_aes_xts(HEADER_KEY, decstr1, True ) == encstr1
  assert crypt_aes_xts(HEADER_KEY, decstr1, False) != encstr1
  assert crypt_aes_xts(HEADER_KEY, encstr1, False) == decstr1
  assert crypt_aes_xts(HEADER_KEY, decstr9, True ) != encstr9  # Longer than 512 bytes, different.
  assert crypt_aes_xts(HEADER_KEY, decstr9, True )[:512] == encstr9[:512]
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
  assert crypt_aes_xts(HEADER_KEY[:48], decstr6, True ) == encstr6
  assert crypt_aes_xts(HEADER_KEY[:48], encstr6, False) == decstr6
  assert crypt_aes_xts(HEADER_KEY[:32], decstr7, True ) == encstr7
  assert crypt_aes_xts(HEADER_KEY[:32], encstr7, False) == decstr7
  assert crypt_sectors('aes-xts-plain64',   HEADER_KEY, decstr1, True) == encstr1  # Not longer than 12 bytes, same.
  assert crypt_sectors('aes-xts-plain64be', HEADER_KEY, encstr1, False) == decstr1
  assert crypt_sectors('aes-xts-plain',     HEADER_KEY, encstr1, False) == decstr1
  assert crypt_sectors('aes-xts-plain',     HEADER_KEY, encstr3[48:], False, ofs=48) == decstr3[48:]  # Short.
  assert crypt_sectors('aes-xts-plain64',   HEADER_KEY, encstr9[64:], False, ofs=64) == decstr9[64:]  # Longer than a sector.
  assert crypt_sectors('aes-xts-plain64', HEADER_KEY, decstr9, True) == encstr9
  assert crypt_sectors('aes-xts-plain64', HEADER_KEY, encstr9, False) == decstr9
  assert crypt_sectors('aes-xts-plain64', HEADER_KEY[:48], decstr6, True) == encstr6
  assert crypt_sectors('aes-xts-plain64', HEADER_KEY[:48], encstr6, False) == decstr6
  assert crypt_sectors('aes-xts-plain64', HEADER_KEY[:48], crypt_sectors('aes-xts-plain64', HEADER_KEY[:48], decstr1, True), False) == decstr1
  test_vectors = (
      '10070acc039cf6b051456edf104aab998d6aa05235be5d89dbd7219f1c372016d6e7d32527713d80857a610557a402a2'.decode('hex'),
      'a5d0bc7ab7e93856845b2e2f2ea0754bb5b9bbd4aa0787d3db22d4e5b62fa8e4c0b93469c782e5a7074c3c6671f20692'.decode('hex'),
      '804bfc9dd12cbb075e8eb67d34e3cdfedb4b95c9b773fbbaed05f5117f26e36698fe86c219e440a03d70cd8048ffa427'.decode('hex'),
      '392d52ef30b82d367d6fdfc100ca2354f768864af4df2ce9258757b7d147cf48fd230da17aded859fe1fde88b294b136'.decode('hex'),
  )
  help_test_crypt_sectors('aes-xts-', HEADER_KEY[:32], test_vectors)


def test_crypt_aes_cbc():
  crypt_aes_cbc = tinyveracrypt.crypt_aes_cbc
  crypt_aes_cbc_whitening = tinyveracrypt.crypt_aes_cbc_whitening
  key, iv, whitening = '\xaa' * 32, '\xbb' * 16, 'Whitenin'
  decstr1, encstr1 = DECSTR, '39e3eada19066384fb90b9262d108f7476c8eefda65e1995c8c8481a826f64ec4695bd5dacca4a89e4d894cd18710bcb'.decode('hex')
  decstr2, encstr2 = DECSTR, '6242705e2164d05650e8edde48fb2c00f73dd10d280472c4ab350aaa7a5237a42521e599c4b2e3f722b29481bcf65bc8'.decode('hex')
  decstr3, encstr3 = DECSTR, '8cb57f3e2a322fb7a526fa63d92c87c4d5c055c4e4943dd05a2560b1a0c9f9dcff76334cde72cbb77009b4b31c947d16'.decode('hex')
  decstr4, encstr4 = DECSTR, '6e8b83ae7c680aeaacf8d052487ee61a21a08789c33070fb9fa0216ee7010d8211fdd429c9a423e7b3b0fdb97d1f62a5'.decode('hex')
  decstr5, encstr5 = DECSTR, 'e3359fe690e3bf87f83eb761150544d1b43f9ede131cfbff2ead4cc69f972df54028bdedf76f67b9cf30e4bbbcde8aed'.decode('hex')
  assert crypt_aes_cbc(key, '', True, iv) == ''
  assert crypt_aes_cbc(key, '', False, iv) == ''
  assert crypt_aes_cbc(key, decstr1, True,  iv) == encstr1
  assert crypt_aes_cbc(key, encstr1, False, iv) == decstr1
  assert crypt_aes_cbc(key, encstr1, True,  iv) != decstr1
  assert crypt_aes_cbc(key, decstr1[:16], True,  iv) == encstr1[:16]
  assert crypt_aes_cbc(key, encstr1[:16], False, iv) == decstr1[:16]
  assert crypt_aes_cbc(key, decstr1[:32], True,  iv) == encstr1[:32]
  assert crypt_aes_cbc(key, encstr1[:32], False, iv) == decstr1[:32]
  assert crypt_aes_cbc(key, decstr2, True, '\1\4' + '\0' * 14) == encstr2
  assert crypt_sectors('aes-cbc-plain', key, decstr2, True, sector_idx=1025) == encstr2
  assert crypt_aes_cbc_whitening(key, decstr1, True,  iv, '\0') == encstr1
  assert crypt_aes_cbc_whitening(key, encstr1, False, iv, '\0') == decstr1
  assert crypt_aes_cbc_whitening(key, decstr4, True,  iv, whitening) == encstr4
  assert crypt_aes_cbc_whitening(key, encstr4, False, iv, whitening) == decstr4
  assert crypt_aes_cbc_whitening(HEADER_KEY[:32], decstr5, True,  HEADER_KEY[32 : 48], HEADER_KEY[40 : 48]) == encstr5
  assert crypt_aes_cbc_whitening(HEADER_KEY[:32], encstr5, False, HEADER_KEY[32 : 48], HEADER_KEY[40 : 48]) == decstr5
  assert crypt_sectors('aes-cbc-tcw', HEADER_KEY, decstr3, True,  sector_idx=0x98765123456789ab) == encstr3
  assert crypt_sectors('aes-cbc-tcw', HEADER_KEY, decstr3, True,  sector_idx=0x98765123456789ac) != encstr3
  assert crypt_sectors('aes-cbc-tcw', HEADER_KEY, encstr3, False, sector_idx=0x98765123456789ab) == decstr3
  assert crypt_sectors('aes-cbc-tcw', HEADER_KEY, decstr3[:48], True,  sector_idx=0x98765123456789ab) == encstr3[:48]
  assert crypt_sectors('aes-cbc-tcw', HEADER_KEY, encstr3[:48], False, sector_idx=0x98765123456789ab) == decstr3[:48]
  test_vectors = (
      '8c178626a94130779366ccef39f3c3a06569b37511e04d8a853a19fb8a47928b0612ccf644352cbc78e7ceb2c5662c3d'.decode('hex'),
      'b4d4e70a9c006c75ff9f61cae0793d0e299f8f6c4879377ae49a078455b16844616f576ff40c710a3a2236807d87b53c'.decode('hex'),
      '5d66afd4b445ddba9f084303e88fc4530276b69f6bbdd949236778fa4dd6a3f88c3c0fa347a46e5da46c58eefae73678'.decode('hex'),
      '9f85e36c0483188d1dbbf304bd7498c20f114d455c7c4cc893e38bc665cc17503c94bc98c1429d1f01c03992ebe3e1aa'.decode('hex'),
  )
  help_test_crypt_sectors('aes-cbc-', HEADER_KEY[:32], test_vectors)


def test_gf2pow128mul():
  gf2pow128mul = tinyveracrypt.gf2pow128mul
  assert gf2pow128mul(0xb9623d587488039f1486b2d8d9283453, 0xa06aea0265e84b8a) == 0xfead2ebe0998a3da7968b8c2f6dfcbd2
  assert gf2pow128mul(0x0696ce9a49b10a7c21f61cea2d114a22, 0x8258e63daab974bc) == 0x89a493638cea727c0bb06f5e9a0248c7
  assert gf2pow128mul(0xecf10f64ceff084cd9d9d1349c5d1918, 0xf48a39058af0cf2c) == 0x80490c2d2560fe266a5631670c6729c1
  assert gf2pow128mul(0x9c65a83501fae4d5672e54a3e0612727, 0x9d8bc634f82dfc78) == 0xd0c221b4819fdd94e7ac8b0edc0ab2cb
  assert gf2pow128mul(0xb8885a52910edae3eb16c268e5d3cbc7, 0x98878367a0f4f045) == 0xa6f1a7280f1a89436f80fdd5257ec579
  assert gf2pow128mul(0xd91376456609fac6f85748784c51b272, 0xf6d1fa7f5e2c73b9) == 0xbcbb318828da56ce0008616226d25e28
  assert gf2pow128mul(0x0865625a18a1aace15dba90dedd95d27, 0x395fcb20c3a2a1ff) == 0xa1c704fc6e913666c7bd92e3bc2cbca9
  assert gf2pow128mul(0x45ff1a2274ed22d43d31bb224f519fea, 0xd94a263495856bc5) == 0xd0f6ce03966ba1e1face79dfce89e830
  assert gf2pow128mul(0x0508aaf2fdeaedb36109e8f830ff2140, 0xc15154674dea15bf) == 0x67e0dbe4ddff54458fa67af764d467dd
  assert gf2pow128mul(0xaec8b76366f66dc8e3baaf95020fdfb5, 0xd1552daa9948b824) == 0x0a3c509baed65ac69ec36ae7ad03cc24
  assert gf2pow128mul(0x1c2ff5d21b5555781bbd22426912aa58, 0x5cdda0b2dafbbf2e) == 0xc9f85163d006bebfc548d010b6590cf2
  assert gf2pow128mul(0x1d4db0dfb7b12ea8d431680ac07ba73b, 0xa9913078a5c26c9b) == 0x6e71eaf1e7276f893a9e98a377182211
  assert gf2pow128mul(0xf7d946f08e94d545ce583b409322cdf6, 0x73c174b844435230) == 0xad9748630fd502fe9e46f36328d19e8d
  assert gf2pow128mul(0xdeada9ae22eff9bc3c1669f824c46823, 0x6bdd94753484db33) == 0xc40822f2f3984ed58b24bd207b515733
  assert gf2pow128mul(0x8146e084b094a0814577558be97f9be1, 0xb3fdd171a771c2ef) == 0xf0093a3df939fe1922c6a848abfdf474
  assert gf2pow128mul(0x7c468425a3bda18a842875150b58d753, 0x6358fcb8015c9733) == 0x369c44a03648219e2b91f50949efc6b4
  assert gf2pow128mul(0xe5f445041c8529d28afad3f8e6b76721, 0x06cefb145d7640d1) == 0x8c96b0834c896435fe8d4a70c17a8aff
  assert gf2pow128mul(0xe5f445041c8529d28afad3f8e6b76721, 0xaec8b76366f66dc8e3baaf95020fdfb5) == 0x8051e17110ae04e02c47d1fc167837b0


def test_crypt_aes_lrw():
  crypt_aes_lrw = tinyveracrypt.crypt_aes_lrw
  crypt_aes_lrw_zerobased = tinyveracrypt.crypt_aes_lrw_zerobased
  key = HEADER_KEY[:48]
  decstr1, encstr1 = DECSTR, '8220a9fa19715f06f83eb761150544d152f823ff8e3b1fd969236ac5517305c957695a49b707c2f7be8fe57f1a359afc'.decode('hex')
  decstr2, encstr2 = DECSTR, 'b840f1d6568366e51d47ee92ef1b264633be2e1267b5d478e0f84f9c5841bdaf96a43afafd1e9d27d2bb02870e28a1ed'.decode('hex')
  decstr9, encstr9 = 'Help!' * 206 + 10 * '\0', '35a7f4d0fa7a752daa35cd865f0844fbb84426a3cf506151b33242369c7e6ae2ed2fd493b16ca3629724729eb7b49bab2590de79ca0a175c06fa1cc3c71db26e56cafb1b455a1bc7207dcd64e8c8602c7ddc4cba199594e28a459c0e3bec6b15a42603bae3099d983a0ac777bcd608083679c8afbf2098841535da23c1af49e26ed134fd9675dc811afac6b3794159b9876ee0b158aea7f7c86e3b547cf0872fd9ec85d1406f2b443c1dfca273b2d67ddf864ce70e8b4c16cb9b4dfd4b8d0e690d13ce3f19b664216a9aae65b4d4a5e62092daaf4b3668702ad2201e0b0b7f0556aaad9048bf97700929e41179744191b8d123b2b8dd24ef04666e07a55bf7bd60d640879ed7870fda68d19deacb90b8a92e55ca30a53606cc8c287ec2226433e16ba386c070707a162e9ff4a6055b033dcd691db347ae49d7193eca6d8e7d703df7a0210facfa9af3a91d8d95173c4c76c2b3fad4c48dd9eb0290435768d1489a4556ce3eb86e103f7d06cd012c48fd2130a2688b5e94a902401389797dbb65097e2799bfc7b334553f164b199754f6ab40423b563b49801dbd1d8202fafb86f1429c8f0da813c70f9b3fa4fa6d10e94fd65ca6db67ead56df182e3a9c6214797b9b912ffa43806be8618cb4233c14d7a4c21cee34221894fd5f125556edce23b11f27ae85c4478100f1e87b5101351f2deca5de8a2afaa589a9d6fb0e76b46f9677c0fb0c9e1d88ce1276fd51ce1a10f0792915119adb06a8f956912de25b0f6940ef7b9f54475c0b98673955477457f38d939ab8194ce860289948be8b2c2cfd86524718ea63873f52e4f54cc8540bd84bf4b432e0b301e8baebedd48d542780cbf8dde72215b44185a97a47d7edca2fd4dc2850b01e27a8d74de5a1454b42054f426a6fec96569cfcf89ce612f0f4f4ea398d408ee60542abcdb622b79f7bc5258052dcf95a4a43dccdfd6908f224e758d4eea0eaff794f8f9b3c09b8ddbd9011fb38e0099c9bb3ad4960f6ab52e0a574c92569a31d08a4be5a292ebda2d94f03ac536cbea6bb9c82a531ed594ce3770a4bb9a2494279fb0556647c7e6df7dbafc5076097e33c330c68f29d03eeb56b96191d582bb80769b00911b81e42195b3b4c5fed79aee73db20cf7a44d8c8165ebe21d7c920f9984288f9ecf0a4b99c8defbbc62829b019c81b9cd3daaae23a545c5a3bd240c6d8951a50791db399d6a808d24edd83fa20633ecdfe6908e86259fdabf8d04f05a10a801af6b48cdcd9dfce67ede3097603782014bd964b2f9232c0921ce42d85531300bc684a3167b03a40840a002b24a8a94d39beee06d3ab7e96841ee4ebacbd434dacf6d7e1a0935c37061d5616ccbb0b4a006f28c7238e34a2d6bbb5b46916a3306771b37b7faa0295dc7d725b5a38cf5f44361b95bf999d7f8c9fa1b524efd55abcf2dae1efee38c95fbc5d6742277f3f90c62768ac'.decode('hex')
  assert crypt_aes_lrw(key, '', True ) == ''
  assert crypt_aes_lrw(key, '', False) == ''
  assert crypt_aes_lrw(key, decstr1, True ) == encstr1
  assert crypt_aes_lrw(key, encstr1, False) == decstr1
  assert crypt_aes_lrw(key, encstr1, True ) != decstr1
  assert crypt_aes_lrw(key, decstr1[:16], True ) == encstr1[:16]
  assert crypt_aes_lrw(key, encstr1[:16], False) == decstr1[:16]
  assert crypt_aes_lrw(key, decstr1[:32], True ) == encstr1[:32]
  assert crypt_aes_lrw(key, encstr1[:32], False) == decstr1[:32]
  assert crypt_aes_lrw(key, decstr2, True,  block_idx=321) == encstr2
  assert crypt_aes_lrw(key, encstr2, False, ofs=5120) == decstr2
  encstr1zb = crypt_aes_lrw_zerobased(key, decstr1, True)
  assert encstr1zb != encstr1
  assert crypt_aes_lrw_zerobased(key, decstr1, True, ofs=16) == encstr1
  assert crypt_sectors('aes-lrw-plain64',   key, decstr1, True) == encstr1zb
  assert crypt_sectors('aes-lrw-plain64be', key, decstr1, True) == encstr1zb
  assert crypt_sectors('aes-lrw-plain',     key, decstr1, True) == encstr1zb
  assert crypt_sectors('aes-lrw-benbi', key, decstr2, True,  sector_idx=10) == encstr2
  assert crypt_sectors('aes-lrw-benbi', key, encstr2, False, sector_idx=10) == decstr2
  assert crypt_sectors('aes-lrw-benbi', key, decstr1[:32], True ) == encstr1[:32]
  assert crypt_sectors('aes-lrw-benbi', key, encstr1[:32], False) == decstr1[:32]
  assert crypt_sectors('aes-lrw-benbi', key, decstr9, True ) == encstr9
  assert crypt_sectors('aes-lrw-benbi', key, encstr9, False) == decstr9
  assert crypt_sectors('aes-lrw-plain64', key, decstr1, True, ofs=16) == encstr1  # Short.
  assert crypt_sectors('aes-lrw-plain64', key, decstr9, True, ofs=16) != encstr9  # Longer than a sector.
  assert crypt_sectors('aes-lrw-benbi', key, encstr2[16:], False, ofs=16, sector_idx=10) == decstr2[16:]  # Short.
  assert crypt_sectors('aes-lrw-benbi', key, encstr9[64:], False, ofs=64) == decstr9[64:]  # Longer than a sector.
  assert crypt_sectors('aes-lrw-plain', key, decstr1[16:], True, ofs=16) == encstr1zb[16:]  # Short.
  test_vectors = (
      'b3dbfe70608c674c4429846191cf80cb9ca5a35d7d3ba0bf2769bd39ccb5191be70e755265de11594e15bf0f82b07a5a'.decode('hex'),
      'c5a7c64eb5e9a9dfdc8d52fe6c2dbb088e9bfb0264747b7c3dbc0e41557373bc525ba054edbfbd2fb3505b32b235525a'.decode('hex'),
      '3ee29537196d22928c96201bf30a11c6944ecb4b2c2afa04fe32f0c062d7a6626b3a2c4b0c88bcbcb9cb9b1273c4330f'.decode('hex'),
      '055b0043764a4d7e25464287fc73f3b25345901f00f230773858e05e0d9fad5ee609368787061b3fb588e6d5430c06db'.decode('hex'),
  )
  help_test_crypt_sectors('aes-lrw-', HEADER_KEY[:32], test_vectors)


def test_crypt_by_ofs():
  a, b = 'The quick brown fox jumps over the lazy dog. Pad', 'That kept the rooster that crowe'
  c, d = 'This is the horse and the hound and the horn,   ', 'That belonged to the farmer sowi'
  assert not (len(a) & 15 or len(b) & 15 or len(c) & 15 or len(d) & 15)
  for cipher, crypt_func in sorted(tinyveracrypt.CRYPT_BY_OFS_MAX_512_FUNCS.iteritems()):
    key = HEADER_KEY[:(64, 48)[cipher.startswith('aes-lrw-')]]
    abenc = crypt_func(key, a + b, True)
    assert crypt_func(key, a, True) == abenc[:len(a)]
    assert crypt_func(key, b, True) != abenc[-len(b):]
    assert crypt_func(key, b, True, ofs=len(a)) == abenc[-len(b):]
    assert crypt_func(key, abenc, False) == a + b
    assert crypt_func(key, abenc[-len(b):], False) != b
    assert crypt_func(key, abenc[-len(b):], False, ofs=len(a)) == b
    cdenc = crypt_func(key, c + d, True)
    assert crypt_func(key, abenc[:len(a)] + cdenc[-len(b):], False) == a + d


def test_crypt_for_veracrypt_header():
  crypt_for_veracrypt_header = tinyveracrypt.crypt_for_veracrypt_header
  # These test vectors are copied from other tests above.
  decstr1, encstr1 = 'abcdef' * 5 + 'x', '900fb0b4eb5751d04f4141c59c1f4b0563dc58441d957bec7696f1a1a71ceb'.decode('hex')
  decstr2, encstr2 = DECSTR, '8220a9fa19715f06f83eb761150544d152f823ff8e3b1fd969236ac5517305c957695a49b707c2f7be8fe57f1a359afc'.decode('hex')
  decstr3, encstr3 = DECSTR, 'e3359fe690e3bf87f83eb761150544d1b43f9ede131cfbff2ead4cc69f972df54028bdedf76f67b9cf30e4bbbcde8aed'.decode('hex')
  assert crypt_for_veracrypt_header('aes-xts-plain64', HEADER_KEY, decstr1, True ) == encstr1
  assert crypt_for_veracrypt_header('aes-xts-plain64', HEADER_KEY, encstr1, False) == decstr1
  assert crypt_for_veracrypt_header('aes-lrw-benbi', HEADER_KEY[32:] + HEADER_KEY[:32], decstr2, True ) == encstr2
  assert crypt_for_veracrypt_header('aes-lrw-benbi', HEADER_KEY[32:] + HEADER_KEY[:32], encstr2, False) == decstr2
  assert crypt_for_veracrypt_header('aes-cbc-tcw', HEADER_KEY[32:] + HEADER_KEY[:32], decstr3, True ) == encstr3
  assert crypt_for_veracrypt_header('aes-cbc-tcw', HEADER_KEY[32:] + HEADER_KEY[:32], encstr3, False) == decstr3


def test_veracrypt():
  check_full_dechd = tinyveracrypt.check_full_dechd
  build_dechd = tinyveracrypt.build_dechd
  parse_dechd = tinyveracrypt.parse_dechd
  build_table = tinyveracrypt.build_table
  crypt_veracrypt_encdechd = tinyveracrypt.crypt_veracrypt_encdechd

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

  check_full_dechd(dechd, 0, False)
  assert build_dechd(SALT, keytable, decrypted_size, sector_size) == dechd
  assert parse_dechd(dechd, 'aes-xts-plain64', 65536) == (keytable, decrypted_size, decrypted_ofs)
  table = build_table(keytable, decrypted_size, decrypted_ofs, raw_device, decrypted_ofs, 'aes-xts-plain64', True, (), True)
  expected_table = '0 72 crypt aes-xts-plain64 a64cd0845765a19b0b5948f371f0b8c7b14da01677a10009d8b9199d511624233a54e1118dd6c9e2992e3ebae56081ca1f996c74c53f61f1a48f7fb17ddc6d5b 256 7:0 256 1 allow_discards\n'
  assert build_table('K' * 32, 51200, 12800, 'raw.img', 8, 'aes-xts-plain64', False, (), False) == '0 100 crypt aes-xts-plain64 0000000000000000000000000000000000000000000000000000000000000000 0 raw.img 25\n'
  assert table == expected_table
  assert crypt_veracrypt_encdechd(dechd, HEADER_KEY, cipher='aes-xts-plain64', do_encrypt=True) == enchd
  assert crypt_veracrypt_encdechd(enchd, HEADER_KEY, cipher='aes-xts-plain64', do_encrypt=False) == dechd
  dechd2 = dechd[:-32] + '\1\1' + dechd[-30:]
  enchd2 = crypt_veracrypt_encdechd(dechd2, HEADER_KEY, cipher='aes-xts-plain64', do_encrypt=True)
  i = 0
  while i < len(enchd) and enchd[:len(enchd) - i] != enchd2[: len(enchd) - i]:
    i += 1
  # print 'CHANGED', i
  assert i == 32, i

  rec = tinyveracrypt.get_recommended_veracrypt_decrypted_ofs
  assert rec(1 << 30, False) == 2 << 20  # No need for more than 2 MiB alignment.
  assert rec(512 << 20, False) == 2 << 20  # At most 0.4% overhead, good SSD block alignment (same as default 2 MiB LUKS header size by cryptsetup).
  assert rec(256 << 20, False) == 1 << 20  # At most 0.4% overhead, good SSD block alignment (same as default 1 MiB partition alignment).
  assert rec(128 << 20, False) == 512 << 10
  assert rec(4 << 20, False) == 16 << 10  # At most 0.4% overhead, good SSD page alignment.
  assert rec((4 << 20) - 1, False) == 8 << 10
  assert rec(2 << 20, False) == 8 << 10  # At most 0.4% overhead, good SSD page alignment.
  assert rec((2 << 20) - 1, False) == 4 << 10
  assert rec(1 << 20, False) == 4 << 10  # At most 0.4% overhead, good SSD page alignment.
  assert rec((1 << 20) - 1, False) == 512  # Small overhead.
  assert rec(0, False) == 512
  assert rec(1 << 30, True) == 2 << 20
  assert rec(512 << 20, True) == 2 << 20
  assert rec(256 << 20, True) == 1 << 20
  assert rec(128 << 20, True) == 512 << 10
  assert rec(64 << 20, True) == 256 << 10
  assert rec((64 << 20) - 1, True) == 128 << 10
  assert rec(32 << 20, True) == 128 << 10
  assert rec((32 << 20) - 1, True) == 128 << 10
  assert rec(0, True) == 128 << 10

  utm = tinyveracrypt.update_truecrypt_mode
  assert utm(0, 'tcrypt') == 0
  assert utm(1, 'tcrypt') == 2
  assert utm(2, 'tcrypt') == 2
  assert utm(3, 'tcrypt') == 2
  assert utm(None, 'tcrypt') == 2
  assert utm(0, 'truecrypt') == 2
  assert utm(2, 'veracrypt') == 0
  assert utm(0, 'luks') == 3

  assert tinyveracrypt.get_iterations(None, False, 'sha512') == 500000
  assert tinyveracrypt.get_iterations(None, True, 'sha512') == 1000

  header_key = tinyveracrypt.pbkdf2_hmac(  # Fast, hard-coded.
      'sha512', tinyveracrypt.TEST_PASSPHRASE, tinyveracrypt.TEST_SALT,
      500000, 64)
  enchd = tinyveracrypt.build_veracrypt_header(
      decrypted_size=1 << 20, decrypted_ofs=4096,
      passphrase=tinyveracrypt.TEST_PASSPHRASE,
      enchd_prefix=tinyveracrypt.TEST_SALT, is_hidden=False,
      hash='sha512', cipher='aes-xts-plain64', keytable=keytable)
  dechd = crypt_veracrypt_encdechd(enchd, header_key, 'aes-xts-plain64', False)
  check_full_dechd(dechd, 0, False)
  keytable2, decrypted_size, decrypted_ofs = parse_dechd(
      dechd, 'aes-xts-plain64', (1 << 20 | 1 << 16))
  assert keytable2 == keytable
  assert decrypted_size == 1 << 20
  assert decrypted_ofs == 4096


def test_luks():
  size = 2066432
  decrypted_ofs = 4096 # + 1024, for 8 key slots.
  key_size = 48 << 3
  # keytable = ''.join(map(chr, xrange(32, 32 + (key_size >> 3))))
  keytable = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO'
  # Fast because pbkdf2_hmac is called with extremely small values of
  # keytable_iterations and slot_iterations.
  header = tinyveracrypt.build_luks_header(
      passphrase=(tinyveracrypt.TEST_PASSPHRASE, 'abc'),
      #hash='sha1',
      key_size=key_size,
      af_salt='xyzAB' * 4000,
      af_stripe_count=13,
      decrypted_ofs=decrypted_ofs,
      uuid='40bf7c9f-12a6-403f-81da-c4bd2183b74a',
      keytable_iterations=2, slot_iterations=3,
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
  #open('mkluks_demo.bin', 'w+b').write(full_header)
  del full_header  # Save memory.
  assert tinyveracrypt.build_table(keytable, size - decrypted_ofs, decrypted_ofs, '7:0', 0, 'aes-xts-plain64', True, (), True) == (
      '0 4028 crypt aes-xts-plain64 %s 0 7:0 8 1 allow_discards\n' % keytable.encode('hex'))
  decrypted_ofs2, keytable2, cipher = tinyveracrypt.get_open_luks_info(f=cStringIO.StringIO(''.join((header, header_padding, '\0' * 512))), passphrase='abc')
  assert cipher == 'aes-xts-plain64'
  assert (decrypted_ofs2, keytable2) == (decrypted_ofs, keytable), ((decrypted_ofs2, keytable2), (decrypted_ofs, keytable))
  rec = tinyveracrypt.get_recommended_luks_decrypted_ofs
  assert rec(1 << 30) == 2 << 20  # No need for more than 2 MiB alignment.
  assert rec(512 << 20) == 2 << 20  # At most 0.4% overhead, good SSD block alignment (same as default 2 MiB LUKS header size by cryptsetup).
  assert rec(256 << 20) == 1 << 20  # At most 0.4% overhead, good SSD block alignment (same as default 1 MiB partition alignment).
  assert rec(128 << 20) == 512 << 10
  assert rec(4 << 20) == 16 << 10
  assert rec((4 << 20) - 1) == 8 << 10
  assert rec(2 << 20) == 8 << 10  # At most 0.4% overhead, >= 8192 (so it can store all blocks), good SSD page alignment.
  assert rec((2 << 20) - 1) == 8 << 10  # LUKS cryptsetup minimum, can store at most 6 slots, good SSD page alignment.
  assert rec(1 << 20) == 8 << 10
  assert rec((1 << 20) - 1) == 8 << 10
  assert rec(0) == 8 << 10
  rec = tinyveracrypt.get_recommended_luks_af_stripe_size
  assert rec(1 << 21) == 256000
  assert rec(2001 << 10) == 256000
  assert rec((2001 << 10) - 1) == 251904
  assert rec(160 << 10) == 16 << 10
  assert rec((160 << 10) - 1) == 17920
  assert rec(80 << 10) == 8 << 10
  assert rec(40 << 10) == 4 << 10
  assert rec(28 << 10) == 3 << 10
  assert rec((28 << 10) - 1) == 2560
  assert rec(24 << 10) == 2560
  assert rec((24 << 10) - 1) == 2 << 10
  assert rec(20 << 10) == 2 << 10
  assert rec(18 << 10) == 2 << 10
  assert rec((18 << 10) - 1) == 1536
  assert rec(10 << 10) == 1 << 10
  assert rec((10 << 10) - 1) == 1 << 10
  assert rec(9 << 10) == 1 << 10
  assert rec((9 << 10) - 1) == 512
  assert rec(5 << 10) == 512
  assert rec((5 << 10) - 1) == 512
  assert rec(4096) == 512
  assert rec(1536) == 512
  assert rec(512) == 512
  assert rec(0) == 512


def test():
  test_crc32()
  test_gf2pow128mul()
  test_aes()
  test_sha512()
  test_sha384()
  test_sha256()
  test_sha224()
  test_sha1()
  test_ripemd160()
  test_whirlpool()
  test_md5()
  test_crypt_aes_xts()
  test_crypt_aes_cbc()
  test_crypt_aes_lrw()
  test_crypt_by_ofs()
  test_crypt_for_veracrypt_header()
  test_veracrypt()
  test_luks()


def test_slow():
  print 'SLOW'
  sys.stdout.flush()
  # Takes about 6..60 seconds.
  assert tinyveracrypt.pbkdf2_hmac('sha512', 'foo', SALT, 500000, 64) == HEADER_KEY


if __name__ == '__main__':
  do_slow = False
  i = 1
  while i < len(sys.argv):
    arg = sys.argv[i]
    if arg == '--slow-aes':
      tinyveracrypt.new_aes = tinyveracrypt.SlowAes
    elif arg == '--slow-sha512':
      tinyveracrypt.HASH_DIGEST_PARAMS['sha512'] = (tinyveracrypt.SlowSha512,) + tinyveracrypt.HASH_DIGEST_PARAMS['sha512'][1:]
    elif arg == '--slow-sha384':
      tinyveracrypt.HASH_DIGEST_PARAMS['sha384'] = (tinyveracrypt.SlowSha384,) + tinyveracrypt.HASH_DIGEST_PARAMS['sha384'][1:]
    elif arg == '--slow-sha256':
      tinyveracrypt.HASH_DIGEST_PARAMS['sha256'] = (tinyveracrypt.SlowSha256,) + tinyveracrypt.HASH_DIGEST_PARAMS['sha256'][1:]
    elif arg == '--slow-sha224':
      tinyveracrypt.HASH_DIGEST_PARAMS['sha224'] = (tinyveracrypt.SlowSha224,) + tinyveracrypt.HASH_DIGEST_PARAMS['sha224'][1:]
    elif arg == '--slow-sha1':
      tinyveracrypt.HASH_DIGEST_PARAMS['sha1'] = (tinyveracrypt.SlowSha1,) + tinyveracrypt.HASH_DIGEST_PARAMS['sha1'][1:]
    elif arg == '--slow-ripemd160':
      tinyveracrypt.HASH_DIGEST_PARAMS['ripemd160'] = (tinyveracrypt.SlowRipeMd160,) + tinyveracrypt.HASH_DIGEST_PARAMS['ripemd160'][1:]
    elif arg == '--slow-whirlpool':
      tinyveracrypt.HASH_DIGEST_PARAMS['whirlpool'] = (tinyveracrypt.SlowWhirlpool,) + tinyveracrypt.HASH_DIGEST_PARAMS['whirlpool'][1:]
    elif arg == '--slow-md5':
      tinyveracrypt.HASH_DIGEST_PARAMS['md5'] = (tinyveracrypt.SlowMd5,) + tinyveracrypt.HASH_DIGEST_PARAMS['md5'][1:]
    elif arg == '--slow-crc32':
      tinyveracrypt.crc32 = tinyveracrypt.slow_crc32
    elif arg == '--slow-pbkdf2-hmac':
      tinyveracrypt.pbkdf2_hmac = tinyveracrypt.slow_pbkdf2_hmac
    elif arg == '--slow':
      do_slow = True
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
    if do_slow or len(sys.argv) > i:
      test_slow()
    print __file__, ' OK.'
