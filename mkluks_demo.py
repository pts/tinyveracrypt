#! /usr/bin/python
# by pts@fazekas.hu at Sat Apr 13 17:47:01 CEST 2019

"""mkluks_demo.py: half-written alternative of `cryptsetup luksFormat'"""

#import hashlib  # See below.
import cStringIO
import itertools
import struct
import sys

# --- Library.

TEST_PASSPHRASE = 'ThisIsMyVeryLongPassphraseForMyVeraCryptVolume'

try:
  __import__('Crypto.Util.strxor')
  def make_strxor(size, strxor=sys.modules['Crypto.Util.strxor'].strxor):
    return strxor
except ImportError:
  try:
    bytearray  # Introduced in Python 2.6. Raises NameError in older Python.
    # This is about 26.18% faster than the one below using pack.
    #
    # Using array.array('B', ...) would be a bit slower than using pack.
    def make_strxor(size):
      def strxor(a, b, izip=itertools.izip, ba=bytearray, st=str):
        return st(ba((a ^ b for a, b in izip(ba(a), ba(b)))))
      return strxor
  except NameError:
    # This is the naive implementation, it's too slow:
    #
    # def strxor(a, b, izip=itertools.izip):
    #   return ''.join(chr(ord(x) ^ ord(y)) for x, y in izip(a, b))
    #
    # 58 times slower pure Python implementation, see
    # http://stackoverflow.com/a/19512514/97248
    def make_strxor(size):
      def strxor(a, b, izip=itertools.izip, pack=struct.pack, unpack=struct.unpack, fmt='%dB' % size):
        return pack(fmt, *(a ^ b for a, b in izip(unpack(fmt, a), unpack(fmt, b))))
      return strxor


class SlowAes(object):
    """AES cipher. Slow, but compatible with Crypto.Cipher.AES.new and
    aes.Keysetup.

    Usage:

      ao = SlowAes('key1' * 8)
      assert len(ao.encrypt('plaintext_______')) == 16
      assert len(ao.decrypt('ciphertext______')) == 16
    """

    # --- Initialize the following constants: S, Si, T1, T2, T3, T4, T5, T6, T7, T8, U1, U2, U3, U4, RC.
    #
    # Hardcoding the final values would make the code 14 kB longer.

    # Produce log and alog tables, needed for multiplying in the
    # field GF(2^m) (generator = 3).
    alog = [1]
    for i in xrange(255):
      j = (alog[-1] << 1) ^ alog[-1]
      if j & 0x100 != 0:
        j ^= 0x11B
      alog.append(j)

    log = [0] * 256
    for i in xrange(1, 255):
      log[alog[i]] = i

    # multiply two elements of GF(2^m)
    def mul(a, b, alog, log):
      return a and b and alog[(log[a & 255] + log[b & 255]) % 255]

    # Substitution box based on F^{-1}(x).
    box = [[0] * 8 for i in xrange(256)]
    box[1][7] = 1
    for i in xrange(2, 256):
      j = alog[255 - log[i]]
      for t in xrange(8):
        box[i][t] = (j >> (7 - t)) & 0x01

    A = ((1, 1, 1, 1, 1, 0, 0, 0), (0, 1, 1, 1, 1, 1, 0, 0), (0, 0, 1, 1, 1, 1, 1, 0), (0, 0, 0, 1, 1, 1, 1, 1), (1, 0, 0, 0, 1, 1, 1, 1), (1, 1, 0, 0, 0, 1, 1, 1), (1, 1, 1, 0, 0, 0, 1, 1), (1, 1, 1, 1, 0, 0, 0, 1))
    B = (0, 1, 1, 0, 0, 0, 1, 1)

    # Affine transform:  box[i] <- B + A*box[i].
    cox = [[0] * 8 for i in xrange(256)]
    for i in xrange(256):
      for t in xrange(8):
        cox[i][t] = B[t]
        for j in xrange(8):
          cox[i][t] ^= A[t][j] * box[i][j]

    # S-boxes and inverse S-boxes.
    S, Si =  [0] * 256, [0] * 256
    for i in xrange(256):
      S[i] = cox[i][0] << 7
      for t in xrange(1, 8):
        S[i] ^= cox[i][t] << (7 - t)
      Si[S[i] & 255] = i

    # T-boxes.
    G = ((2, 1, 1, 3), (3, 2, 1, 1), (1, 3, 2, 1), (1, 1, 3, 2))
    AA = [[0] * 8 for i in xrange(4)]
    for i in xrange(4):
      for j in xrange(4):
        AA[i][j] = G[i][j]
        AA[i][i + 4] = 1

    for i in xrange(4):
      pivot = AA[i][i]
      if pivot == 0:
        t = i + 1
        while AA[t][i] == 0 and t < 4:
          t += 1
          assert t != 4, 'G matrix must be invertible.'
          for j in xrange(8):
            AA[i][j], AA[t][j] = AA[t][j], AA[i][j]
          pivot = AA[i][i]
      for j in xrange(8):
        if AA[i][j] != 0:
          AA[i][j] = alog[(255 + log[AA[i][j] & 255] - log[pivot & 255]) % 255]
      for t in xrange(4):
        if i != t:
          for j in xrange(i + 1, 8):
            AA[t][j] ^= mul(AA[i][j], AA[t][i], alog, log)
          AA[t][i] = 0

    iG = [[0] * 4 for i in xrange(4)]
    for i in xrange(4):
      for j in xrange(4):
        iG[i][j] = AA[i][j + 4]

    def mul4(a, bs, mul, alog, log):
      r = 0
      if a:
        for b in bs:
          r <<= 8
          if b:
            r |= mul(a, b, alog, log)
      return r

    T1, T2, T3, T4, T5, T6, T7, T8, U1, U2, U3, U4 = [], [], [], [], [], [], [], [], [], [], [], []
    for t in xrange(256):
      s = S[t]
      T1.append(mul4(s, G[0], mul, alog, log))
      T2.append(mul4(s, G[1], mul, alog, log))
      T3.append(mul4(s, G[2], mul, alog, log))
      T4.append(mul4(s, G[3], mul, alog, log))
      s = Si[t]
      T5.append(mul4(s, iG[0], mul, alog, log))
      T6.append(mul4(s, iG[1], mul, alog, log))
      T7.append(mul4(s, iG[2], mul, alog, log))
      T8.append(mul4(s, iG[3], mul, alog, log))
      U1.append(mul4(t, iG[0], mul, alog, log))
      U2.append(mul4(t, iG[1], mul, alog, log))
      U3.append(mul4(t, iG[2], mul, alog, log))
      U4.append(mul4(t, iG[3], mul, alog, log))

    RC = [1]  # Round constants.
    r = 1
    for t in xrange(1, 30):
      r = mul(2, r, alog, log)
      RC.append(r)

    del A, AA, pivot, B, G, box, log, alog, i, j, r, s, t, mul, mul4, cox, iG

    # --- End of constant initialization.

    __slots__ = ('Ke', 'Kd')

    def __init__(self, key):
      if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise ValueError('Invalid key size: ' + str(len(key)))
      RC, S, U1, U2, U3, U4 = self.RC, self.S, self.U1, self.U2, self.U3, self.U4
      ROUNDS = 6 + (len(key) >> 2)
      Ke = [[0] * 4 for i in xrange(ROUNDS + 1)]  # Encryption round keys.
      Kd = [[0] * 4 for i in xrange(ROUNDS + 1)]  # Decryption round keys.
      RKC = 28 + len(key)  # Round key count.
      KC = len(key) >> 2
      tk = list(struct.unpack('>' + 'L' * KC, key))
      # Copy values into round key arrays.
      t = 0
      while t < KC:
        Ke[t >> 2][t & 3] = tk[t]
        Kd[ROUNDS - (t >> 2)][t & 3] = tk[t]
        t += 1
      tt = ri = 0
      while t < RKC:
        # Extrapolate using phi (the round key evolution function).
        tt = tk[KC - 1]
        tk[0] ^= ((S[(tt >> 16) & 255] & 255) << 24 ^ (S[(tt >> 8) & 255] & 255) << 16 ^ (S[tt & 255] & 255) <<  8 ^ (S[(tt >> 24) & 255] & 255) ^ (RC[ri] & 255) << 24)
        ri += 1
        if KC != 8:
          for i in xrange(1, KC):
            tk[i] ^= tk[i - 1]
        else:
          for i in xrange(1, KC >> 1):
            tk[i] ^= tk[i-1]
          tt = tk[(KC >> 1) - 1]
          tk[KC >> 1] ^= ((S[tt & 255] & 255) ^ (S[(tt >>  8) & 255] & 255) << 8 ^ (S[(tt >> 16) & 255] & 255) << 16 ^ (S[(tt >> 24) & 255] & 255) << 24)
          for i in xrange((KC >> 1) + 1, KC):
            tk[i] ^= tk[i - 1]
        # Copy values into round key arrays.
        j = 0
        while j < KC and t < RKC:
          Ke[t >> 2][t & 3] = tk[j]
          Kd[ROUNDS - (t >> 2)][t & 3] = tk[j]
          j += 1
          t += 1
      # Invert MixColumn where needed.
      for r in xrange(1, ROUNDS):
        for j in xrange(4):
          tt = Kd[r][j]
          Kd[r][j] = (U1[(tt >> 24) & 255] ^ U2[(tt >> 16) & 255] ^ U3[(tt >>  8) & 255] ^ U4[tt & 255])
      self.Ke, self.Kd = Ke, Kd

    def encrypt(self, plaintext):
      Ke, S, T1, T2, T3, T4 = self.Ke, self.S, self.T1, self.T2, self.T3, self.T4
      if len(plaintext) != 16:
        raise ValueError('Wrong block length, expected 16, got: ' + str(len(plaintext)))
      ROUNDS = len(Ke) - 1
      t = struct.unpack('>LLLL', plaintext)
      Ker = Ke[0]
      t = [t[i] ^ Ker[i] for i in xrange(4)] * 2
      for r in xrange(1, ROUNDS):  # Apply round transforms.
        Ker = Ke[r]
        t = [T1[(t[i] >> 24) & 255] ^ T2[(t[i + 1] >> 16) & 255] ^ T3[(t[i + 2] >> 8) & 255] ^ T4[ t[i + 3] & 255] ^ Ker[i] for i in xrange(4)] * 2
      Ker = Ke[ROUNDS]
      return struct.pack('>LLLL', *((S[(t[i] >> 24) & 255] << 24 | S[(t[i + 1] >> 16) & 255] << 16 | S[(t[i + 2] >> 8) & 255] << 8 | S[t[i + 3] & 255]) ^ Ker[i] for i in xrange(4)))

    def decrypt(self, ciphertext):
      Kd, Si, T5, T6, T7, T8 = self.Kd, self.Si, self.T5, self.T6, self.T7, self.T8
      if len(ciphertext) != 16:
        raise ValueError('Wrong block length, expected 16, got: ' + str(len(plaintext)))
      ROUNDS = len(Kd) - 1
      t = struct.unpack('>LLLL', ciphertext)
      Kdr = Kd[0]
      t = [t[i] ^ Kdr[i] for i in xrange(4)] * 2
      for r in xrange(1, ROUNDS):  # Apply round transforms.
        Kdr = Kd[r]
        t = [T5[(t[i] >> 24) & 255] ^ T6[(t[i + 3] >> 16) & 255] ^ T7[(t[i + 2] >> 8) & 255] ^ T8[ t[i + 1] & 255] ^ Kdr[i] for i in xrange(4)] * 2
      Kdr = Kd[ROUNDS]
      return struct.pack('>LLLL', *((Si[(t[i] >> 24) & 255] << 24 | Si[(t[i + 3] >> 16) & 255] << 16 | Si[(t[i + 2] >> 8) & 255] << 8 | Si[t[i + 1] & 255]) ^ Kdr[i] for i in xrange(4)))


def get_best_new_aes(_cache=[]):
  """Returns the fastest new_aes implementation available, falling back to
  SlowAes."""
  if _cache:
    return _cache[0]
  new_aes = None
  if new_aes is None:
    try:
      import Crypto.Cipher._AES
      if type(Crypto.Cipher._AES.new) != type(map):
        raise ImportError
      new_aes = Crypto.Cipher._AES.new
    except (ImportError, AttributeError):
      pass
  if new_aes is None:
    try:
      import Crypto.Cipher.AES
      if type(Crypto.Cipher.AES.new) != type(map):
        raise ImportError
      new_aes = Crypto.Cipher.AES.new
    except (ImportError, AttributeError):
      pass
  if new_aes is None:
    try:
      import aes
      if type(aes.Keysetup.__new__) != type(map):
        raise ImportError
      new_aes = aes.Keysetup
    except (ImportError, AttributeError):
      pass
  if new_aes is None:
    new_aes = SlowAes
  _cache.append(new_aes)
  return new_aes


new_aes = get_best_new_aes()

strxor_16 = make_strxor(16)


def check_aes_xts_key(aes_xts_key):
  if len(aes_xts_key) != 64:
    raise ValueError('aes_xts_key must be 64 bytes, got: %d' % len(aes_xts_key))


# We use pure Python code (from CryptoPlus) for AES XTS encryption. This is
# slow, but it's not a problem, because we have to encrypt only 512 bytes
# per run. Please note that pycrypto-2.6.1 (released on 2013-10-17) and
# other C crypto libraries with Python bindings don't support AES XTS.
#
# For Linux dm-crypt aes-xts-plain64, sector size is 512 bytes, so
# device_ofs == (sector_idx << 9).
def crypt_aes_xts(aes_xts_key, data, do_encrypt, ofs=0, sector_idx=0, codebook1_crypt=None):
  check_aes_xts_key(aes_xts_key)
  if len(data) < 16 and len(data) > 0:
    # TODO(pts): Is there a meaningful result for these short inputs?
    raise ValueError('At least one block of 128 bits needs to be supplied.')
  if len(data) >> 27:
    raise ValueError('data too long.')  # This is an implementation limitation.
  if ofs:
    if ofs & 15:
      raise ValueError('ofs must be divisible by 16, got: %d' % ofs)
    if ofs < 0:
      raise ValueError('ofs must be nonnegative, got: %d' % ofs)
  if sector_idx < 0:
    raise ValueError('sector_idx must be nonnegative, got: %d' % ofs)
  if ofs >= len(data):
    return ''

  # This would work instead of inlining:
  #
  #   import CryptoPlus.Cipher.python_AES
  #   new_aes_xts = lambda aes_xts_key: CryptoPlus.Cipher.python_AES.new((aes_xts_key[:32], aes_xts_key[32 : 64]), CryptoPlus.Cipher.python_AES.MODE_XTS)
  #   cipher = new_aes_xts(aes_xts_key)
  #   if do_encrypt:
  #     return cipher.encrypt(data)
  #   else:
  #     return cipher.decrypt(data)

  pack, do_decrypt = struct.pack, not do_encrypt
  if codebook1_crypt is None:
    codebook1 = new_aes(aes_xts_key[:32])
    codebook1_crypt = (codebook1.encrypt, codebook1.decrypt)[do_decrypt]
    del codebook1

  # sector_idx is LSB-first for aes-xts-plain64, see
  # https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt
  t0, t1 = struct.unpack('<QQ', new_aes(aes_xts_key[32 : 64]).encrypt(pack(
      '<QQ', sector_idx & 0xffffffffffffffff, sector_idx >> 8)))
  t = (t1 << 64) | t0
  for i in xrange(ofs >> 4):
    t <<= 1
    if t >= 0x100000000000000000000000000000000:  # (1 << 128).
      t ^=  0x100000000000000000000000000000087

  def yield_crypt_blocks(t):
    for i in xrange(0, len(data) - 31, 16):
      # Alternative which is 3.85 times slower: t_str = ('%032x' % t).decode('hex')[::-1]
      t_str = struct.pack('<QQ', t & 0xffffffffffffffff, t >> 64)
      yield strxor_16(t_str, codebook1_crypt(strxor_16(t_str, data[i : i + 16])))
      t <<= 1
      if t >= 0x100000000000000000000000000000000:
        t ^=  0x100000000000000000000000000000087

    lm15 = len(data) & 15
    if lm15:  # Process last 2 blocks if len is not a multiple of 16 bytes.
      i, t0, t1 = len(data) & ~15, t, t << 1
      if t1 >= 0x100000000000000000000000000000000:
        t1 ^=  0x100000000000000000000000000000087
      if do_decrypt:
        t0, t1 = t1, t0
      t_str = struct.pack('<QQ', t0 & 0xffffffffffffffff, t0 >> 64)
      pp = strxor_16(t_str, codebook1_crypt(strxor_16(t_str, data[i - 16 : i])))
      t_str = struct.pack('<QQ', t1 & 0xffffffffffffffff, t1 >> 64)
      yield strxor_16(t_str, codebook1_crypt(strxor_16(t_str, data[i:] + pp[lm15:])))
      yield pp[:lm15]
    else:
      t_str = struct.pack('<QQ', t & 0xffffffffffffffff, t >> 64)
      yield strxor_16(t_str, codebook1_crypt(strxor_16(t_str, data[-16:])))

  # TODO(pts): Use even less memory by using an array.array('B', ...).
  return ''.join(yield_crypt_blocks(t))


def crypt_aes_xts_sectors(aes_xts_key, data, do_encrypt, sector_idx=0):
  check_aes_xts_key(aes_xts_key)
  codebook1 = new_aes(aes_xts_key[:32])
  codebook1_crypt = (codebook1.encrypt, codebook1.decrypt)[not do_encrypt]
  del codebook1

  def yield_crypt_sectors(sector_idx):
    i = 0
    while i < len(data):
      if len(data) - i < 16:
        yield crypt_aes_xts(aes_xts_key, data[i:] + '\0' * (16 - (len(data) - i)), do_encrypt, 0, sector_idx, codebook1_crypt)
      else:
        yield crypt_aes_xts(aes_xts_key, data[i : i + 512], do_encrypt, 0, sector_idx, codebook1_crypt)
      sector_idx += 1
      i += 512

  return ''.join(yield_crypt_sectors(sector_idx))


class UsageError(SystemExit):
  """Raised when there is a problem in the command-line."""


def pbkdf2(passphrase, salt, size, iterations, digest_cons, blocksize):
  # Ignore `blocksize'. It's embedded in hash_name.
  import hashlib
  hash_name = digest_cons.__name__.lower()
  if hash_name.startswith('openssl_'):
    hash_name = hash_name[hash_name.find('_') + 1:]
  return hashlib.pbkdf2_hmac(hash_name, passphrase, salt, iterations, size)


def get_random_bytes(size, _functions=[]):
  if size == 0:
    return ''
  if not _functions:
    def manual_random(size):
      return ''.join(chr(random.randrange(0, 255)) for _ in xrange(size))

    try:
      import os
      data = os.urandom(1)
      if len(data) != 1:
        raise ValueError
      _functions.append(os.urandom)
    except (ImportError, AttributeError, TypeError, ValueError, OSError):
      _functions.append(manual_random)

  return _functions[0](size)


def check_keytable(keytable):
  # Same as check_as_xts_key.
  if len(keytable) != 64:
    raise ValueError('keytable must be 64 bytes, got: %d' % len(keytable))


def prompt_passphrase(do_passphrase_twice):
  sys.stderr.flush()
  sys.stdout.flush()
  import getpass
  passphrase = getpass.getpass('Enter passphrase: ')
  if not passphrase:
    raise SystemExit('empty passphrase')
  if do_passphrase_twice:
    passphrase2 = getpass.getpass('Re-enter passphrase: ')
    if passphrase != passphrase2:
      raise SystemExit('passphrases do not match')
  return passphrase


def get_hash_digest_params(hash):
  """Returns (digest_cons, digest_blocksize)."""
  hash2 = hash.lower().replace('-', '')
  if hash2 == 'sha512':
    return sha512, 128
  elif hash2 == 'sha1':
    return sha1, 64
  else:
    raise ValueError('Unsupported hash: %s' % hash)


sha512 = __import__('hashlib').sha512

sha1 = __import__('hashlib').sha1


# ---


def check_luks_decrypted_size(decrypted_size):
  min_decrypted_size = 2066432 - 4096
  if decrypted_size < min_decrypted_size:
    raise ValueError('LUKS decrypted_size must be at least %d bytes, got: %d' %
                     (min_decrypted_size, decrypted_size))
  if decrypted_size & 511:
    raise ValueError('LUKS decrypted_size must be divisible by 512, got: %d' %
                     decrypted_size)


def check_luks_size(size):
  # `cryptsetup luksDump' and `cryptSetup open ... --type=luks' in
  # cryptsetup-1.7.3 both report this error for <2MiB volumes:
  # `LUKS requires at least 2066432 bytes.'.
  min_size = 2066432
  if size < min_size:
    raise ValueError('LUKS size must be at least %d bytes, got: %d' %
                     (min_size, size))
  if size & 511:
    raise ValueError('LUKS size must be divisible by 512, got: %d' % size)


def check_luks_decrypted_ofs(decrypted_ofs):
  if decrypted_ofs < 4096:
    # In 512-byte sectors. Must be larger than key_material_offset, which is
    # at least 2, so payload_offset must be at least 3, thus the encrypted
    # LUKS1 payload is at least 1536 bytes smaller than the device, and the
    # minimum size for a LUKS1 device is 2048 bytes.
    #
    # `cryptsetup luksDump' allows decrypted_ofs >= 1536, but
    # `sudo cryptsetup open ... --type luks' requires decrypted_ofs >= 4096,
    # and fails with
    # `Reduced data offset is allowed only for detached LUKS header.' for
    # cryptsetup-1.7.3 otherwise.
    raise ValueError('decrypted_ofs must be at least 4096, got: %d' % decrypted_ofs)
  if decrypted_ofs & 511:
    raise ValueError('decrypted_ofs must be a multiple of 512, got: %d' % decrypted_ofs)


def check_luks_key_material_ofs(key_material_ofs):
  if key_material_ofs < 1024:
    raise ValueError('key_material_ofs must be nonnegative, got: %d' % key_material_ofs)
  if key_material_ofs & 511:
    raise ValueError('key_material_ofs must be a multiple of 512, got: %d' % key_material_ofs)


def get_iterations(pim, is_truecrypt=False):
  if pim:
    return 15000 + 1000 * pim
  elif is_truecrypt:
    # TrueCrypt 5.0 SHA-512 has 1000 iterations (corresponding to --pim=-14),
    # see: https://gitlab.com/cryptsetup/cryptsetup/wikis/TrueCryptOnDiskFormat
    return 1000
  else:
    # --pim=485 corresponds to iterations=500000
    # (https://www.veracrypt.fr/en/Header%20Key%20Derivation.html says that
    # for --hash=sha512 iterations == 15000 + 1000 * pim).
    return 500000


def check_iterations(iterations):
  if not isinstance(iterations, (int, long)):
    raise TypeError
  # LUKS allows 1 and above.
  if iterations <= 0:
    raise ValueError('iterations must be positive, got: %d' % iterations)


def check_luks_keytable_salt(keytable_salt):
  if len(keytable_salt) != 32:
    raise ValueError('LUKS keytable_salt must be 32 bytes, got: %d' %
                     len(keytable_salt))


def check_luks_slot_salt(slot_salt):
  if len(slot_salt) != 32:
    raise ValueError('LUKS slot_salt must be 32 bytes, got: %d' %
                     len(slot_salt))


def luks_af_hash_h1(data, output_size, digest_cons):
  if output_size <= 0:
    raise ValueError('af_hash_h1 output_size must be at least 1, got: %d' %
                     output_size)
  digest_size = len(digest_cons().digest())
  assert digest_size > 0
  output = [digest_cons('\0\0\0\0' + data[:digest_size]).digest()]
  for i in xrange(digest_size, output_size, digest_size):
    output.append(digest_cons(struct.pack('>L', i // digest_size) + data[i : i + digest_size]).digest())
  i = output_size % digest_size
  if i:
    output[-1] = output[-1][:i]
  return ''.join(output)


def check_stripe_count(stripe_count):
  if stripe_count <= 0:
    raise ValueError('luks_af_split stripe_count must be at least 1, got: %d' %
                     stripe_count)


def luks_af_split(data, stripe_count, digest_cons, random_data=None):
  """Returns an anti-forensic multiplication of data by stripe_count."""
  check_stripe_count(stripe_count)
  if not data or stripe_count == 1:  # Shortcut.
    return str(data)
  size = len(data)
  d, strxor = '\0' * size, make_strxor(size)
  random_data_size = (stripe_count - 1) * size
  if random_data:
    if len(random_data) < random_data_size:
      raise ValueError('luks_af_split random_data must be %d bytes, got: %d' %
                       (random_data_size, len(random_data)))
  else:
    random_data = get_random_bytes(random_data_size)
  for n in xrange(0, random_data_size, size):
    d = luks_af_hash_h1(strxor(d, random_data[n : n + size]), size, digest_cons)
    assert len(d) == size, (len(d), size)
  # Of size len(data) * stripe_count.
  return random_data[:random_data_size] + strxor(d, data)


def luks_af_join(data, stripe_count, digest_cons):
  check_stripe_count(stripe_count)
  if not data or stripe_count == 1:  # Shortcut.
    return str(data)
  if len(data) % stripe_count:
    raise ValueError('luks_af_join data size must be divisble by stripe_count=%d, got: %d' %
                     (stripe_count, len(data)))
  size = len(data) // stripe_count
  d, strxor = '\0' * size, make_strxor(size)
  for n in xrange(0, len(data) - size, size):
    d = luks_af_hash_h1(strxor(d, data[n : n + size]), size, digest_cons)
    assert len(d) == size, (len(d), size)
  return strxor(d, data[-size:])


def build_luks_active_key_slot(
    slot_iterations, slot_salt, keytable, passphrase,
    digest_cons, digest_blocksize, key_material_ofs, stripe_count,
    af_salt=None):
  check_keytable(keytable)
  check_luks_key_material_ofs(key_material_ofs)
  if not slot_salt:
    slot_salt = get_random_bytes(32)
  check_luks_slot_salt(slot_salt)
  active_tag = 0xac71f3
  # If there is any invalid keyslot, then
  # `sudo /sbin/cryptsetup luksOpen mkluks_demo.bin foo --debug' will fail
  # without considering other keyslots.
  split_key = luks_af_split(keytable, stripe_count, digest_cons, af_salt)
  key_material_size = len(keytable) * stripe_count
  assert len(split_key) == key_material_size
  assert luks_af_join(split_key, stripe_count, digest_cons) == keytable
  aes_xts_key_size = 64
  header_key = pbkdf2(  # Slow.
      passphrase, slot_salt, aes_xts_key_size, slot_iterations, digest_cons,
      digest_blocksize)
  key_material = crypt_aes_xts_sectors(header_key, split_key, do_encrypt=True)
  assert len(key_material) == key_material_size
  key_slot_data = struct.pack(
      '>LL32sLL', active_tag, slot_iterations, slot_salt, key_material_ofs >> 9,
      stripe_count)
  assert len(key_slot_data) == 48
  return key_slot_data, key_material


def build_luks_inactive_key_slot(slot_iterations, key_material_ofs):
  check_luks_key_material_ofs(key_material_ofs)
  inactive_stripe_count = 1
  inactive_tag = 0xdead
  return struct.pack(
      '>LL32xLL', inactive_tag, slot_iterations, key_material_ofs >> 9,
      inactive_stripe_count)


def build_luks_header(
    passphrase, decrypted_ofs=4096, keytable_salt=None,
    uuid_str=None, pim=None, keytable_iterations=None, slot_iterations=None,
    cipher='aes-xts-plain64', hash='sha512', keytable=None, slot_salt=None,
    af_stripe_count=1, af_salt=None):
  """Builds a LUKS1 header.

  Similar to `cryptsetup luksFormat', with the following differences:

  * Anti-forensic stripe count is 1, to make the header shorter. (This also
    provides no protection against forensic analysis after key slot removal.)
  * By default (decrypted_ofs=4096), the header supports only 6 key slots
    (instead of the `cryptsetup luksFormat' default of 8).
    Specify decrypted_ofs=4608 for 7 key slots, or secrypted_ofs>=5120 for 8
    key slots.
  * Supports only --hash=sha512 and --cipher=aes-xts-plain64. The
    `cryptsetup luksFormat' default is --hash=sha1 --cipher=aes-xts-plain64.
  * Doesn't try to autodetect iteration count based on CPU speed.
  * Specify pim=-14 to make PBKDF2 faster, but only do it if you have a very
    strong, randomly generated password of at least 64 bytes of entropy.
  * It's more configurable (e.g. decrypted_ofs and af_stripe_count).
  * The default for af_stripe_count is smaller than the 4000 of
    `cryptsetup luksFormat'.
  * `cryptsetup luksAddKey' will fail if af_stripe_count < 4000 (default).

  Returns:
    String containing the LUKS1 partition header (phdr) and the key material.
    To open it, copy it to the beginning of a raw device, and use
    `sudo cryptsetup open ... --type=luks'.
  """
  # Based on https://gitlab.com/cryptsetup/cryptsetup/blob/master/docs/on-disk-format.pdf
  # version 1.2.3.
  if cipher == 'aes-xts-plain64':
    cipher_name, cipher_mode, keytable_size = 'aes', 'xts-plain64', 64
  else:
    raise ValueError('Unsupported LUKS cipher: %s' % cipher)
  key_material_sector_count = (af_stripe_count * keytable_size + 511) >> 9
  if decrypted_ofs is None:
    # Make room for all 8 key slots.
    decrypted_ofs = (2 + 8 * key_material_sector_count) << 9
  check_luks_decrypted_ofs(decrypted_ofs)

  # 6 slots for the default decrypted_ofs == 4096.
  slot_count = min(8, ((decrypted_ofs >> 9) - 2) // key_material_sector_count)
  if slot_count <= 0:
    raise ValueError('Not enough room for slots, increase decrypted_ofs to %d or decrease af_stripe_count to %d.' %
                     ((2 + key_material_sector_count) << 9, (decrypted_ofs - 1024) // keytable_size))
  if isinstance(passphrase, str):
    passphrases = (passphrase,)
  else:
    passphrases = passphrase
  if not passphrases:
    # `cryptsetup luksDump' allows it, but there is no way to recover keytable
    # in this situation.
    raise ValueError('Missing LUKS passphrases.')
  if len(passphrases) > slot_count:
    if len(passphrases) <= 8 and slot_count < 8:
      raise ValueError('Too many LUKS passphrases, increase decrypted_ofs to %d or decrease af_stripe_count.' %
                       ((2 + len(passphrases) * key_material_sector_count) << 9))
    else:
      raise ValueError('LUKS passphrase count must be at most %d, got: %d' % (slot_count, len(passphrases)))
  if not uuid_str:
    uuid_str = get_random_bytes(16).encode('hex')
    uuid_str = '-'.join((  # Add the dashes.
        uuid_str[:8], uuid_str[8 : 12], uuid_str[12 : 16],
        uuid_str[16 : 20], uuid_str[20:]))
  # Any random 16 bytes will do, typically it looks like:
  # '40bf7c9f-12a6-403f-81da-c4bd2183b74a'.
  if '\0' in uuid_str:
    raise ValueError('NUL not allowed in LUKS uuid: %r' % uuid_str)
  if len(uuid_str) > 36:
    raise ValueError(
        'LUKS uuid must be at most 36 bytes: %r' % uuid_str)
  if keytable_iterations is None:
    keytable_iterations = get_iterations(pim)
  elif pim:
    raise ValueError('Both pim= and keytable_iterations= are specified.')
  check_iterations(keytable_iterations)
  if slot_iterations is None:
    slot_iterations = get_iterations(pim)  # TODO(pts): Halven it?
  elif pim:
    raise ValueError('Both pim= and slot_iterations= are specified.')
  check_iterations(slot_iterations)
  if not keytable_salt:
    keytable_salt = get_random_bytes(32)
  check_luks_keytable_salt(keytable_salt)
  if not keytable:
    keytable = get_random_bytes(keytable_size)
  elif len(keytable) != keytable_size:
    # keytable is called ``master_key' by LUKS.
    raise ValueError('keytable must be %d bytes, got %d' %
                     (keytable_size, len(keytable)))
  digest_cons, digest_blocksize = get_hash_digest_params(hash)

  signature = 'LUKS\xba\xbe'
  version = 1
  mk_digest = pbkdf2(  # Slow.
      keytable, keytable_salt, 20, keytable_iterations,
      digest_cons, digest_blocksize)

  output = [struct.pack(
      '>6sH32s32s32sLL20s32sL40s',
      signature, version, cipher_name, cipher_mode, hash, decrypted_ofs >> 9,
      keytable_size, mk_digest, keytable_salt, keytable_iterations, uuid_str)]
  key_materials = []
  if slot_count < 8:
    sys.stderr.write('warning: only %d of 8 slots are usable, increase decrypted_ofs to %d or decrease af_stripe_count to %d to get all\n' %
                     (slot_count, (2 + 8 * key_material_sector_count) << 9, ((decrypted_ofs - 1024) >> 12 << 9) // keytable_size))
  for i in xrange(8):
    key_material_ofs = (2 + min(i, slot_count - 1) * key_material_sector_count) << 9
    if i < len(passphrases):
      # Let build_luks_active_key_slot generate random slot_salt values if
      # needed.
      key_slot_data, key_material = build_luks_active_key_slot(
          slot_iterations, slot_salt, keytable, passphrases[i],
          digest_cons, digest_blocksize, key_material_ofs, af_stripe_count,
          af_salt)
      assert key_material
      key_material_padding_size = (key_material_sector_count << 9) - len(key_material)
      assert key_material_padding_size >= 0
      assert len(key_slot_data) == 48
      output.append(key_slot_data)
      key_materials.append(key_material)
      key_materials.append('\0' * key_material_padding_size)
      del key_slot_data, key_material
    else:
      output.append(build_luks_inactive_key_slot(
          slot_iterations, key_material_ofs))
      if i < slot_count:
        key_materials.append('\0' * (key_material_sector_count << 9))
  output.append('\0' * 432)
  output.extend(key_materials)
  result = ''.join(output)
  assert not len(result) & 511
  assert len(result) <= decrypted_ofs
  return result


def luks_open(f, passphrase):
  """Returns (decrypted_ofs, keytable) or raises an exception."""
  f.seek(0)
  header = f.read(592)
  if len(header) < 592:
    raise ValueError('Too short for LUKS1.')
  if not header.startswith('LUKS\xba\xbe\0\1'):
    raise ValueError('LUKS1 signature not found.')
  (signature, version, cipher_name, cipher_mode, hash, decrypted_sector_idx,
   keytable_size, mk_digest, keytable_salt, keytable_iterations, uuid_str,
  ) = struct.unpack('>6sH32s32s32sLL20s32sL40s', buffer(header, 0, 208))
  decrypted_ofs = decrypted_sector_idx << 9
  cipher_name = cipher_name.rstrip('\0')
  cipher_mode = cipher_mode.rstrip('\0')
  hash = hash.rstrip('\0')
  uuid_str = uuid_str.rstrip('\0')
  if cipher_name.lower() != 'aes':
    raise ValueError('Unsupported cipher: %r' % cipher_name)
  if cipher_mode.lower().replace('-', '') != 'xtsplain64':  # 'xts-plain64'.
    raise ValueError('Unsupported cipher mode: %r' % cipher_mode)
  digest_cons, digest_blocksize = get_hash_digest_params(hash)
  # TODO(pts): Check decrypted_sector_idx >= ... like cryptsetup.
  if keytable_size != 64:
    raise ValueError('keytable_size must be 64 for aes-xts-plain64, got: %d' % keytable_size)
  if decrypted_sector_idx < 3:  # `cryptsetup open' also checks this.
    raise ValueError('decrypted_sector_idx must be at leasst 3, got: %d' % decrypted_sector_idx)
  active_slots = []
  for slot_idx in xrange(8):
    slot_active_tag, slot_iterations, slot_salt, slot_key_material_sector_idx, slot_stripe_count = struct.unpack(
        '>LL32sLL', buffer(header, 208 + 48 * slot_idx, 48))
    if slot_active_tag == 0xac71f3:
      # TODO(pts): Report slot_idx in error messages.
      if not slot_iterations:
        raise ValueError('slot_iterations must be at least 1, got: %d' % slot_iterations)
      if not slot_stripe_count:
        raise ValueError('slot_stripe_count must be at least 1, got: %d' % slot_stripe_count)
      if slot_key_material_sector_idx < 2:  # `cryptsetup open' also checks this.
        raise ValueError('slot_key_material_sextor_idx must be at least 2, got: %d' % slot_key_material_sector_idx)
      slot_key_material_size = slot_stripe_count * keytable_size
      minimum_decrypted_sector_idx = slot_key_material_sector_idx + ((slot_key_material_size + 511) >> 9)
      if decrypted_sector_idx < minimum_decrypted_sector_idx:  # `cryptsetup open' also checks this.
        raise ValueError('decrypted_sector_idx must be at least %d because of an active slot, got: %d' %
                         (minimum_decrypted_sector_idx, decrypted_sector_idx))
      active_slots.append((slot_idx, slot_iterations, slot_key_material_sector_idx, slot_stripe_count, slot_salt))
    elif slot_active_tag != 0xdead:
      raise ValueError('Unknown slot_active_tag: 0x%x' % slot_active_tag)
  if not active_slots:
    raise ValueError('No active slots found, it\'s impossible to open the volume even with a correct password.')
  print >>sys.stderr, 'info: found %d active slot%s' % (len(active_slots), 's' * (len(active_slots) != 1))
  if passphrase is None:
    passphrase = prompt_passphrase(False)
  for slot_idx, slot_iterations, slot_key_material_sector_idx, slot_stripe_count, slot_salt in active_slots:
    f.seek(slot_key_material_sector_idx << 9)
    slot_key_material_size = slot_stripe_count * keytable_size
    slot_key_material = f.read(slot_key_material_size)
    if len(slot_key_material) < slot_key_material_size:
      raise ValueError('EOF in slot %d key material on raw device.' % slot_idx)
    aes_xts_key_size = 64
    slot_header_key = pbkdf2(  # Slow.
        passphrase, slot_salt, aes_xts_key_size, slot_iterations, digest_cons,
        digest_blocksize)
    slot_split_key = crypt_aes_xts_sectors(slot_header_key, slot_key_material, do_encrypt=False)
    slot_keytable = luks_af_join(slot_split_key, slot_stripe_count, digest_cons)
    slot_mk_digest = pbkdf2(  # Slow.
        slot_keytable, keytable_salt, 20, keytable_iterations,
        digest_cons, digest_blocksize)
    if slot_mk_digest == mk_digest:
      print >>sys.stderr, 'info: passphrase correct for slot %d' % slot_idx
      break
    print >>sys.stderr, 'info: passphrase incorrect for slot %d' % slot_idx
  else:
    raise ValueError('Incorrect passphrase.')
  f.seek(decrypted_ofs)
  if len(f.read(512)) != 512:
    raise ValueError('decrypted_ofs beyond end of raw device.')
  return decrypted_ofs, slot_keytable


def build_luks_table(
    keytable, decrypted_size, decrypted_ofs, raw_device,
    opt_params=('allow_discards',)):
  # Return value has same syntax as of `dmsetup table --showkeys' and what
  # `dmsetup create' expects.
  # https://www.kernel.org/doc/Documentation/device-mapper/dm-crypt.txt
  check_luks_decrypted_size(decrypted_size)
  check_luks_decrypted_ofs(decrypted_ofs)
  check_keytable(keytable)
  start_offset_on_logical = 0
  cipher = 'aes-xts-plain64'
  target_type = 'crypt'
  iv_offset = 0
  if opt_params:
    opt_params_str = ' %d %s' % (len(opt_params), ' '.join(opt_params))
  else:
    opt_params_str = ''
  return '%d %d %s %s %s %d %s %s%s\n' % (
      start_offset_on_logical, decrypted_size >> 9, target_type,
      cipher, keytable.encode('hex'),
      iv_offset >> 9, raw_device, decrypted_ofs >> 9, opt_params_str)


def main(argv):
  # Command with similar output: /sbin/cryptsetup luksFormat --batch-mode --cipher=aes-xts-plain64 --hash=sha1 --use-urandom mkluks_demo.bin
  size = 2066432
  check_luks_size(size)
  decrypted_ofs = 4096 # + 1024, for 8 key slots.
  keytable = ''.join(map(chr, xrange(3, 67)))
  header = build_luks_header(
      passphrase=(TEST_PASSPHRASE, 'abc'),
      #pim=-14,
      #hash='sha1',
      af_salt='xyzAB' * 4000,
      af_stripe_count=13,
      decrypted_ofs=decrypted_ofs,
      uuid_str='40bf7c9f-12a6-403f-81da-c4bd2183b74a',
      keytable_iterations=2, slot_iterations=3, # pim=-14,
      keytable=keytable,
      slot_salt=''.join(map(chr, xrange(6, 38))),
      keytable_salt=''.join(map(chr, xrange(32))),
      )
  header_padding = 'H' * (decrypted_ofs - len(header))
  payload0 = crypt_aes_xts(keytable, 'Hello,_ ' * 64, do_encrypt=True, sector_idx=0)
  payload1 = crypt_aes_xts(keytable, 'World!_ ' * 64, do_encrypt=True, sector_idx=1)
  payload2 = 'P' * (size - decrypted_ofs - len(payload0) - len(payload1))
  full_header = ''.join((header, header_padding, payload0, payload1, payload2))
  # Accepted by: ./mkluks_demo.py && /sbin/cryptsetup luksDump --debug mkluks_demo.bin
  open('mkluks_demo.bin', 'w+b').write(full_header)
  del full_header  # Save memory.
  sys.stdout.write(build_luks_table(keytable, size - decrypted_ofs, decrypted_ofs, '7:0'))
  decrypted_ofs2, keytable2 = luks_open(f=cStringIO.StringIO(''.join((header, header_padding, '\0' * 512))), passphrase='abc')
  assert (decrypted_ofs2, keytable2) == (decrypted_ofs, keytable), ((decrypted_ofs2, keytable2), (decrypted_ofs, keytable))


if __name__ == '__main__':
  sys.exit(main(sys.argv))
