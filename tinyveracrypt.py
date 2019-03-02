#! /bin/sh
# by pts@fazekas.hu at Sat Oct 29 19:43:26 CEST 2016

""":" #tinyveracrypt: VeraCrypt-compatible block device encryption setup

type python2.7 >/dev/null 2>&1 && exec python2.7 -- "$0" ${1+"$@"}
type python2.6 >/dev/null 2>&1 && exec python2.6 -- "$0" ${1+"$@"}
type python2.5 >/dev/null 2>&1 && exec python2.5 -- "$0" ${1+"$@"}
type python2.4 >/dev/null 2>&1 && exec python2.4 -- "$0" ${1+"$@"}
exec python -- ${1+"$@"}; exit 1

This script works with Python 2.5, 2.6 and 2.7 out of the box, and with
Python 2.4 if the hashlib is installed from PyPi. It doesn't work with older
versions of Python or Python 3.x.
"""

import binascii
import itertools
import struct
import sys

# --- strxor.

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


# ---  AES XTS crypto code.
#
# Code based on from CryptoPlus (2014-11-17): https://github.com/doegox/python-cryptoplus/commit/a5a1f8aecce4ddf476b2d80b586822d9e91eeb7d
#
# Uses make_strxor above.
#

class SlowAes(object):
    """AES cipher. Slow, but compatible with Crypto.Cipher.AES.new and
    aes.Keysetup.

    Usage:

      ao = SlowAes('key1' * 8)
      assert len(ao.encrypt('plaintext_______')) == 16
      assert len(ao.decrypt('ciphertext______')) == 16
    """

    # --- Initialize the following constants: [S, Si, T1, T2, T3, T4, T5, T6, T7, T8, U1, U2, U3, U4, rcon.

    A = [[1, 1, 1, 1, 1, 0, 0, 0],
         [0, 1, 1, 1, 1, 1, 0, 0],
         [0, 0, 1, 1, 1, 1, 1, 0],
         [0, 0, 0, 1, 1, 1, 1, 1],
         [1, 0, 0, 0, 1, 1, 1, 1],
         [1, 1, 0, 0, 0, 1, 1, 1],
         [1, 1, 1, 0, 0, 0, 1, 1],
         [1, 1, 1, 1, 0, 0, 0, 1]]

    # produce log and alog tables, needed for multiplying in the
    # field GF(2^m) (generator = 3)
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
        if a == 0 or b == 0:
            return 0
        return alog[(log[a & 0xFF] + log[b & 0xFF]) % 255]

    # substitution box based on F^{-1}(x)
    box = [[0] * 8 for i in xrange(256)]
    box[1][7] = 1
    for i in xrange(2, 256):
        j = alog[255 - log[i]]
        for t in xrange(8):
            box[i][t] = (j >> (7 - t)) & 0x01

    B = [0, 1, 1, 0, 0, 0, 1, 1]

    # affine transform:  box[i] <- B + A*box[i]
    cox = [[0] * 8 for i in xrange(256)]
    for i in xrange(256):
        for t in xrange(8):
            cox[i][t] = B[t]
            for j in xrange(8):
                cox[i][t] ^= A[t][j] * box[i][j]

    # S-boxes and inverse S-boxes
    S =  [0] * 256
    Si = [0] * 256
    for i in xrange(256):
        S[i] = cox[i][0] << 7
        for t in xrange(1, 8):
            S[i] ^= cox[i][t] << (7-t)
        Si[S[i] & 0xFF] = i

    # T-boxes
    G = [[2, 1, 1, 3],
        [3, 2, 1, 1],
        [1, 3, 2, 1],
        [1, 1, 3, 2]]

    AA = [[0] * 8 for i in xrange(4)]

    for i in xrange(4):
        for j in xrange(4):
            AA[i][j] = G[i][j]
            AA[i][i+4] = 1

    for i in xrange(4):
        pivot = AA[i][i]
        if pivot == 0:
            t = i + 1
            while AA[t][i] == 0 and t < 4:
                t += 1
                assert t != 4, 'G matrix must be invertible'
                for j in xrange(8):
                    AA[i][j], AA[t][j] = AA[t][j], AA[i][j]
                pivot = AA[i][i]
        for j in xrange(8):
            if AA[i][j] != 0:
                AA[i][j] = alog[(255 + log[AA[i][j] & 0xFF] - log[pivot & 0xFF]) % 255]
        for t in xrange(4):
            if i != t:
                for j in xrange(i+1, 8):
                    AA[t][j] ^= mul(AA[i][j], AA[t][i], alog, log)
                AA[t][i] = 0

    iG = [[0] * 4 for i in xrange(4)]

    for i in xrange(4):
        for j in xrange(4):
            iG[i][j] = AA[i][j + 4]

    def mul4(a, bs, mul, alog, log):
        if a == 0:
            return 0
        r = 0
        for b in bs:
            r <<= 8
            if b != 0:
                r = r | mul(a, b, alog, log)
        return r

    T1 = []
    T2 = []
    T3 = []
    T4 = []
    T5 = []
    T6 = []
    T7 = []
    T8 = []
    U1 = []
    U2 = []
    U3 = []
    U4 = []

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

    # round constants
    rcon = [1]
    r = 1
    for t in xrange(1, 30):
        r = mul(2, r, alog, log)
        rcon.append(r)

    del A, AA, pivot, B, G, box, log, alog, i, j, r, s, t, mul, mul4, cox, iG


    # --- End of constant initialization.

    __slots__ = ('Ke', 'Kd')

    def __init__(self, key):
        if len(key) != 16 and len(key) != 24 and len(key) != 32:
            raise ValueError('Invalid key size: ' + str(len(key)))
        rcon, S, U1, U2, U3, U4 = self.rcon, self.S, self.U1, self.U2, self.U3, self.U4
        ROUNDS = 6 + (len(key) >> 2)
        # encryption round keys
        Ke = [[0] * 4 for i in xrange(ROUNDS + 1)]
        # decryption round keys
        Kd = [[0] * 4 for i in xrange(ROUNDS + 1)]
        ROUND_KEY_COUNT = (ROUNDS + 1) * 4
        KC = len(key) / 4

        # copy user material bytes into temporary ints
        tk = []
        for i in xrange(0, KC):
            tk.append((ord(key[i * 4]) << 24) | (ord(key[i * 4 + 1]) << 16) |
                (ord(key[i * 4 + 2]) << 8) | ord(key[i * 4 + 3]))

        # copy values into round key arrays
        t = 0
        j = 0
        while j < KC and t < ROUND_KEY_COUNT:
            Ke[t / 4][t & 3] = tk[j]
            Kd[ROUNDS - (t / 4)][t & 3] = tk[j]
            j += 1
            t += 1
        tt = 0
        rconpointer = 0
        while t < ROUND_KEY_COUNT:
            # extrapolate using phi (the round key evolution function)
            tt = tk[KC - 1]
            tk[0] ^= ((S[(tt >> 16) & 0xFF] & 0xFF) << 24 ^
                      (S[(tt >>  8) & 0xFF] & 0xFF) << 16 ^
                      (S[ tt        & 0xFF] & 0xFF) <<  8 ^
                      (S[(tt >> 24) & 0xFF] & 0xFF)       ^
                      (rcon[rconpointer]    & 0xFF) << 24)
            rconpointer += 1
            if KC != 8:
                for i in xrange(1, KC):
                    tk[i] ^= tk[i-1]
            else:
                for i in xrange(1, KC / 2):
                    tk[i] ^= tk[i-1]
                tt = tk[KC / 2 - 1]
                tk[KC / 2] ^= ((S[ tt        & 0xFF] & 0xFF)       ^
                               (S[(tt >>  8) & 0xFF] & 0xFF) <<  8 ^
                               (S[(tt >> 16) & 0xFF] & 0xFF) << 16 ^
                               (S[(tt >> 24) & 0xFF] & 0xFF) << 24)
                for i in xrange(KC / 2 + 1, KC):
                    tk[i] ^= tk[i-1]
            # copy values into round key arrays
            j = 0
            while j < KC and t < ROUND_KEY_COUNT:
                Ke[t / 4][t & 3] = tk[j]
                Kd[ROUNDS - (t / 4)][t & 3] = tk[j]
                j += 1
                t += 1
        # inverse MixColumn where needed
        for r in xrange(1, ROUNDS):
            for j in xrange(4):
                tt = Kd[r][j]
                Kd[r][j] = (U1[(tt >> 24) & 0xFF] ^
                            U2[(tt >> 16) & 0xFF] ^
                            U3[(tt >>  8) & 0xFF] ^
                            U4[ tt        & 0xFF])
        self.Ke = Ke
        self.Kd = Kd

    def encrypt(self, plaintext):
      Ke, S, T1, T2, T3, T4 = self.Ke, self.S, self.T1, self.T2, self.T3, self.T4
      if len(plaintext) != 16:
        raise ValueError('wrong block length, expected 16, got ' + str(len(plaintext)))
      ROUNDS = len(Ke) - 1
      t = struct.unpack('>LLLL', plaintext)
      Ker = Ke[0]
      t = [t[i] ^ Ker[i] for i in xrange(4)] * 2
      for r in xrange(1, ROUNDS):  # Apply round transforms.
        Ker = Ke[r]
        t = [T1[(t[i] >> 24) & 0xFF] ^ T2[(t[i + 1] >> 16) & 0xFF] ^ T3[(t[i + 2] >> 8) & 0xFF] ^ T4[ t[i + 3] & 0xFF] ^ Ker[i] for i in xrange(4)] * 2
      Ker = Ke[ROUNDS]
      return struct.pack('>LLLL', *((S[(t[i] >> 24) & 0xFF] << 24 | S[(t[i + 1] >> 16) & 0xFF] << 16 | S[(t[i + 2] >> 8) & 0xFF] << 8 | S[t[i + 3] & 0xFF]) ^ Ker[i] for i in xrange(4)))

    def decrypt(self, ciphertext):
      Kd, Si, T5, T6, T7, T8 = self.Kd, self.Si, self.T5, self.T6, self.T7, self.T8
      if len(ciphertext) != 16:
        raise ValueError('wrong block length, expected 16, got ' + str(len(plaintext)))
      ROUNDS = len(Kd) - 1
      t = struct.unpack('>LLLL', ciphertext)
      Kdr = Kd[0]
      t = [t[i] ^ Kdr[i] for i in xrange(4)] * 2
      for r in xrange(1, ROUNDS):  # Apply round transforms.
        Kdr = Kd[r]
        t = [T5[(t[i] >> 24) & 0xFF] ^ T6[(t[i + 3] >> 16) & 0xFF] ^ T7[(t[i + 2] >> 8) & 0xFF] ^ T8[ t[i + 1] & 0xFF] ^ Kdr[i] for i in xrange(4)] * 2
      Kdr = Kd[ROUNDS]
      return struct.pack('>LLLL', *((Si[(t[i] >> 24) & 0xFF] << 24 | Si[(t[i + 3] >> 16) & 0xFF] << 16 | Si[(t[i + 2] >> 8) & 0xFF] << 8 | Si[t[i + 1] & 0xFF]) ^ Kdr[i] for i in xrange(4)))


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

# ---

strxor_16 = make_strxor(16)


def check_aes_xts_key(aes_xts_key):
  if len(aes_xts_key) != 64:
    raise ValueError('aes_xts_key must be 64 bytes, got: %d' % len(aes_xts_key))


# We use pure Python code (from CryptoPlus) for AES XTS encryption. This is
# slow, but it's not a problem, because we have to encrypt only 512 bytes
# per run. Please note that pycrypto-2.6.1 (released on 2013-10-17) and
# other C crypto libraries with Python bindings don't support AES XTS.
def crypt_aes_xts(aes_xts_key, data, do_encrypt, ofs=0, sector_idx=0):
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
  codebook1 = new_aes(aes_xts_key[:32])
  codebook1_crypt = (codebook1.encrypt, codebook1.decrypt)[do_decrypt]

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


# ---

# Helpers for do_hmac.
hmac_trans_5C = ''.join(chr(x ^ 0x5C) for x in xrange(256))
hmac_trans_36 = ''.join(chr(x ^ 0x36) for x in xrange(256))


# Faster than `import hmac' because of less indirection.
def do_hmac(key, msg, digest_cons, blocksize):
  outer = digest_cons()
  inner = digest_cons()
  if len(key) > blocksize:
    key = digest_cons(key).digest()
    # Usually inner.digest_size <= blocksize, so now len(key) < blocksize.
  key += '\0' * (blocksize - len(key))
  outer.update(key.translate(hmac_trans_5C))
  inner.update(key.translate(hmac_trans_36))
  inner.update(msg)
  outer.update(inner.digest())
  return outer.digest()


has_sha512_hashlib = has_sha512_openssl_hashlib = False
try:
  __import__('hashlib').sha512
  has_sha512_hashlib = True
  has_sha512_openssl_hashlib = __import__('hashlib').sha512.__name__.startswith('openssl_')
except (ImportError, AttributeError):
  pass
has_sha512_pycrypto = False
try:
  __import__('Crypto.Hash._SHA512')
  has_sha512_pycrypto = True
except ImportError:
  pass
if has_sha512_openssl_hashlib:  # Fastest.
  sha512 = sys.modules['hashlib'].sha512
elif has_sha512_pycrypto:
  # Faster than: Crypto.Hash.SHA512.SHA512Hash
  sha512 = sys.modules['Crypto.Hash._SHA512'].new
elif has_sha512_hashlib:
  sha512 = sys.modules['hashlib'].sha512
else:
  # Using a pure Python implementation here would be too slow, because
  # sha512 is used in pbkdf2.
  #
  # This happens in vanilla Python 2.4.
  raise ImportError(
      'Cannot find SHA512 implementation: install hashlib or pycrypto, '
      'or upgrade to Python >=2.5.')


# Faster than `import pbkdf2' (available on pypi) or `import
# Crypto.Protocol.KDF', because of less indirection.
def pbkdf2(passphrase, salt, size, iterations, digest_cons, blocksize):
  """Computes an binary key from a passphrase using PBKDF2.

  This is deliberately slow (to make dictionary-based attacks on passphrase
  slower), especially when iterations is high.
  """
  # strxor is the slowest operation in pbkdf2. For example, for
  # iterations=500000, digest_cons=sha512, len(passphrase) == 3, calls to
  # strxor take 0.2s with Crypto.Util.strxor.strxor, and 11.6s with the pure
  # Python make_strxor above. Other operations within the pbkdf2 call take
  # about 5.9s if hashlib.sha512 is used, and 12.4s if
  # Crypto.Hash._SHA512.new (also implemented in C) is used.

  _do_hmac = do_hmac
  key, i, k = [], 1, size
  while k > 0:
    u = previousu = _do_hmac(passphrase, salt + struct.pack('>I', i), digest_cons, blocksize)
    _strxor = make_strxor(len(u))
    for j in xrange(iterations - 1):
      previousu = _do_hmac(passphrase, previousu, digest_cons, blocksize)
      u = _strxor(u, previousu)
    key.append(u)
    k -= len(u)
    i += 1
  return ''.join(key)[:size]


try:
  if (has_sha512_openssl_hashlib and
      getattr(__import__('hashlib'), 'pbkdf2_hmac', None)):
    # If pbkdf2_hmac is available (since Python 2.7.8), use it. This is a
    # speedup from 8.8s to 7.0s user time, in addition to openssl_sha512.
    #
    # TODO(pts): Also use https://pypi.python.org/pypi/backports.pbkdf2 , if
    # available and it uses OpenSSL.
    def pbkdf2(passphrase, salt, size, iterations, digest_cons, blocksize):
      # Ignore `blocksize'. It's embedded in hash_name.
      import hashlib
      hash_name = digest_cons.__name__.lower()
      if hash_name.startswith('openssl_'):
        hash_name = hash_name[hash_name.find('_') + 1:]
      return hashlib.pbkdf2_hmac(hash_name, passphrase, salt, iterations, size)
except ImportError:
  pass


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


def check_keytable_or_keytablep(keytable):
  if len(keytable) not in (64, 256):
    raise ValueError('keytable must be 64 or 256 bytes, got: %d' % len(keytable))


def check_header_key(header_key):
  if len(header_key) != 64:
    raise ValueError('header_key must be 64 bytes, got: %d' % len(header_key))


def check_dechd(dechd):
  if len(dechd) != 512:
    raise ValueError('dechd must be 512 bytes, got: %d' % len(dechd))


def check_sector_size(sector_size):
  if sector_size < 512 or sector_size & (sector_size - 1):
    raise ValueError('sector_size must be a power of 2 at least 512: %d' % sector_size)


def check_salt(salt):
  if len(salt) != 64:
    raise ValueError('salt must be 64 bytes, got: %d' % len(salt))


def check_decrypted_ofs(decrypted_ofs):
  if decrypted_ofs < 0:
    # The value of 0 works with veracrypt.
    # Typical value is 0x20000 for non-hidden volumes.
    raise ValueError('decrypted_size must be nonnegative, got: %d' % decrypted_ofs)
  if decrypted_ofs & 511:
    # TODO(pts): What does aes_xts require as minimum? 16?
    raise ValueError('decrypted_ofs must be a multiple of 512, got: %d' % decrypted_ofs)

def check_decrypted_size(decrypted_size):
  if decrypted_size & 511:
    raise ValueError('decrypted_size must be a multiple of 512, got: %d' % decrypted_size)
  if decrypted_size <= 0:
    raise ValueError('decrypted_size must be positive, got: %d' % decrypted_size)


def check_table_name(name):
  if '/' in name or '\0' in name or not name or name.startswith('-'):
    raise UsageError('invalid dmsetup table name: %r' % name)
  if name == 'control':
    raise UsageError('disallowed dmsetup table name: %r' % name)


def build_dechd(
    salt, keytable, decrypted_size, sector_size, decrypted_ofs=None,
    zeros_data=None, zeros_ofs=None, is_truecrypt=False):
  check_keytable_or_keytablep(keytable)
  check_decrypted_size(decrypted_size)
  check_salt(salt)
  check_sector_size(sector_size)
  check_decrypted_size(decrypted_size)
  if decrypted_ofs is None:
    decrypted_ofs = 0x20000
  check_decrypted_ofs(decrypted_ofs)
  keytablep = keytable + '\0' * (256 - len(keytable))
  keytable = None  # Unused. keytable[:64]
  keytablep_crc32 = ('%08x' % (binascii.crc32(keytablep) & 0xffffffff)).decode('hex')
  # Constants are based on what veracrypt-1.17 generates.
  signature = ('VERA', 'TRUE')[bool(is_truecrypt)]
  header_format_version = 5
  minimum_version_to_extract = ((1, 11), (5, 0))[bool(is_truecrypt)]
  hidden_volume_size = 0
  flag_bits = 0
  # https://gitlab.com/cryptsetup/cryptsetup/wikis/TrueCryptOnDiskFormat (contains all encryption, hash, count etc. for TrueCrypt, but not for VeraCrypt)
  # https://www.veracrypt.fr/en/VeraCrypt%20Volume%20Format%20Specification.html
  # https://www.veracrypt.fr/en/Encryption%20Algorithms.html
  # TODO(pts): Add TrueCrypt support: signature: "TRUE", --pim=-14 (iterations == 1000), --encryption=aes, --hash=sha512, introduced in TrueCrypt 5.0.
  # --- 0: VeraCrypt hd sector starts here
  # 0 + 64: salt
  # --- 64: header starts here
  # 64 + 4: signature: "VERA": 56455241
  # 68 + 2: header_format_version: Volume header format version: 0005
  # 70 + 2: minimum_version_to_extract: Minimum program version to open (1.11): 010b
  # 72 + 4: keytablep_crc32: CRC-32 of the keytable + keytablep (decrypted bytes 256..511): ????????
  # 76 + 16: zeros16: 00000000000000000000000000000000
  # 92 + 8: hidden_volume_size: size of hidden volume (0 for non-hidden): 0000000000000000
  # 100 + 8: decrypted_size: size of decrypted volume: ????????????????
  # 108 + 8: decrypted_ofs: offset of encrypted area from 0 (beginning of salt), i.e. byte offset of the master key scope (typically 0x20000): 0000000000020000
  # 116 + 8: decrypted_size_b: size of the encrypted area within the master key scope (same as size of the decrypted volume): ????????????????
  # 124 + 4: flag_bits: flag bits (0): 00000000
  # 128 + 4: sector_size: sector size (512 -- shouldn't it be 4096?): 00000200
  # 132 + 120: zeros120: 00..00
  # --- 252: header ends here
  # 252 + 4: header_crc32: CRC-32 of header
  # 256 + 64: keytable (used as key by `dmsetup table' after hex-encoding)
  # 320 + 192: keytable_padding: typically zeros, but can be anything: 00..00
  # --- 512: VeraCrypt hd sector ends here
  #
  # We can overlap this header with FAT12 and FAT16. FAT12 and FAT16
  # filesystem headers fit into our salt. See 'mkinfat'.
  #
  # We can't overlap this header with XFS (e.g. set_xfs_id.py), because XFS
  # filesystem headers conflict with this header (decrypted_size vs
  # xfs.sectsize, byte_offset_for_key vs xfs.label, sector_size vs
  # xfs.icount, flag_bits vs xfs.blocklog etc.).
  if zeros_data is not None:
    if zeros_ofs < 132 or zeros_ofs + len(zeros_data) > 252:
      raise ValueError('zeros_data and zeros_ofs in wrong interval.')
    zeros120 = ''.join(('\0' * (zeros_ofs - 132), zeros_data))
  elif zeros_ofs is not None:
    raise ValueError('zeros_ofs implies zeros_data.')
  else:
    zeros120 = ''
  header = struct.pack(
      '>4sHBB4s16xQQQQLL120s', signature, header_format_version,
      minimum_version_to_extract[0], minimum_version_to_extract[1],
      keytablep_crc32, hidden_volume_size, decrypted_size,
      decrypted_ofs, decrypted_size, flag_bits, sector_size, zeros120)
  assert len(header) == 188
  header_crc32 = ('%08x' % (binascii.crc32(header) & 0xffffffff)).decode('hex')
  dechd = ''.join((salt, header, header_crc32, keytablep))
  assert len(dechd) == 512
  return dechd


def check_full_dechd(dechd, enchd_suffix_size=0, is_truecrypt=False):
  """Does a full, after-decryption check on dechd.

  This is also used for passphrase: on a wrong passphrase, dechd is 512
  bytes of garbage.

  The checks here are more strict than what `cryptsetup' or the mount
  operation of `veracrypt' does. They can be relaxed if the need arises.
  """
  check_dechd(dechd)
  if enchd_suffix_size > 192:
    raise ValueError('enchd_suffix_size too large, got: %s' % enchd_suffix_size)
  signature = ('VERA', 'TRUE')[bool(is_truecrypt)]
  if dechd[64 : 64 + 4] != signature:  # Or 'TRUE'.
    raise ValueError('Signature mismatch.')
  if dechd[72 : 76] != ('%08x' % (binascii.crc32(dechd[256 : 512]) & 0xffffffff)).decode('hex'):
    raise ValueError('keytablep_crc32 mismatch.')
  if dechd[252 : 256] != ('%08x' % (binascii.crc32(dechd[64 : 252]) & 0xffffffff)).decode('hex'):
    raise ValueError('header_crc32 mismatch.')
  header_format_version, = struct.unpack('>H', dechd[68 : 68 + 2])
  if not (5 <= header_format_version <= 9):
    raise ValueError('header_format_version mismatch.')
  minimum_version_to_extract = struct.unpack('>BB', dechd[70 : 70 + 2])
  #if minimum_version_to_extract != (1, 11):
  if ((not is_truecrypt and minimum_version_to_extract[0] != 1) or
      (is_truecrypt and minimum_version_to_extract[0] not in (5, 6, 7))):
    raise ValueError('minimum_version_to_extract mismatch.')
  if dechd[76 : 76 + 16].lstrip('\0'):
    raise ValueError('Missing NUL padding at 76.')
  hidden_volume_size, = struct.unpack('>Q', dechd[92 : 92 + 8])
  if hidden_volume_size:
    # Hidden volume detected here, but currently this tool doesn't support
    # hidden volumes.
    raise ValueError('Unexpected hidden volume.')
  decrypted_size, = struct.unpack('>Q', dechd[100 : 100 + 8])
  if decrypted_size >> 50:  # Larger than 1 PB is insecure.
    raise ValueError('Volume too large.')
  check_decrypted_size(decrypted_size)
  decrypted_ofs, = struct.unpack('>Q', dechd[108 : 108 + 8])
  check_decrypted_ofs(decrypted_ofs)
  encrypted_area_size, = struct.unpack('>Q', dechd[116 : 116 + 8])
  if encrypted_area_size != decrypted_size:
    raise ValueError('encrypted_area_size mismatch.')
  flag_bits, = struct.unpack('>L', dechd[124 : 124 + 4])
  if flag_bits:
    raise ValueError('flag_bits mismatch.')
  sector_size, = struct.unpack('>L', dechd[128 : 128 + 4])
  check_sector_size(sector_size)
  # `veracrypt' and `cryptsetup --mode tcrypt --veracrypt' don't check these
  # bytes.
  #
  # * dechd[160 : 208] is used by --fake-luks=uuid=... .
  # * dechd[380 : 512] is used by --mkfat=... , but that's covered by
  #   enchd_suffix_size=132.
  #if dechd[132 : 132 + 120].lstrip('\0'):
  #  # Does actual VeraCrypt check this? Does cryptsetup --veracrypt check this?
  #  raise ValueError('Missing NUL padding at 132.')
  if dechd[132 : 132 + 28].lstrip('\0'):
    # Does actual VeraCrypt check this? Does cryptsetup --veracrypt check this?
    raise ValueError('Missing NUL padding at 132.')
  if dechd[256 + 64 : 512 - ((enchd_suffix_size + 15) & ~15)].lstrip('\0'):
    # Does actual VeraCrypt check this? Does cryptsetup --veracrypt check this?
    raise ValueError('Missing NUL padding after keytable.')


def build_table(keytable, decrypted_size, decrypted_ofs, raw_device):
  check_keytable(keytable)
  check_decrypted_size(decrypted_size)
  if isinstance(raw_device, (list, tuple)):
    raw_device = '%d:%s' % tuple(raw_device)
  cipher = 'aes-xts-plain64'
  iv_offset = offset = decrypted_ofs
  start_offset_on_logical = 0
  opt_params = ('allow_discards',)
  if opt_params:
    opt_params_str = ' %d %s' % (len(opt_params), ' '.join(opt_params))
  else:
    opt_params_str = ''
  # https://www.kernel.org/doc/Documentation/device-mapper/dm-crypt.txt
  return '%d %d crypt %s %s %d %s %s%s\n' % (
      start_offset_on_logical, decrypted_size >> 9,
      cipher, keytable.encode('hex'),
      iv_offset >> 9, raw_device, offset >> 9, opt_params_str)


def encrypt_header(dechd, header_key):
  check_dechd(dechd)
  check_header_key(header_key)
  enchd = dechd[:64] + crypt_aes_xts(header_key, dechd[64 : 512], do_encrypt=True)
  assert len(enchd) == 512
  return enchd


def decrypt_header(enchd, header_key):
  if len(enchd) != 512:
    raise ValueError('enchd must be 512 bytes, got: %d' % len(enchd))
  check_header_key(header_key)
  dechd = enchd[:64] + crypt_aes_xts(header_key, enchd[64 : 512], do_encrypt=False)
  assert len(dechd) == 512
  return dechd


# Slow, takes about 6..60 seconds.
def build_header_key(passphrase, salt_or_enchd, pim=None, is_truecrypt=False):
  if len(salt_or_enchd) < 64:
    raise ValueError('Salt too short.')
  salt = salt_or_enchd[:64]
  if pim:
    iterations = 15000 + 1000 * pim
  elif is_truecrypt:
    # TrueCrypt 5.0 SHA-512 has 1000 iterations (corresponding to --pim=-14),
    # see: https://gitlab.com/cryptsetup/cryptsetup/wikis/TrueCryptOnDiskFormat
    iterations = 1000
  else:
    # --pim=485 corresponds to iterations=500000
    # (https://www.veracrypt.fr/en/Header%20Key%20Derivation.html says that
    # for --hash=sha512 iterations == 15000 + 1000 * pim).
    iterations = 500000
  # Speedup for testing.
  if passphrase == 'ThisIsMyVeryLongPassphraseForMyVeraCryptVolume' and iterations == 500000:
    if salt == "~\xe2\xb7\xa1M\xf2\xf6b,o\\%\x08\x12\xc6'\xa1\x8e\xe9Xh\xf2\xdd\xce&\x9dd\xc3\xf3\xacx^\x88.\xe8\x1a6\xd1\xceg\xebA\xbc]A\x971\x101\x163\xac(\xafs\xcbF\x19F\x15\xcdG\xc6\xb3":
      return '\x11Q\x91\xc5h%\xb2\xb2\xf0\xed\x1e\xaf\x12C6V\x7f+\x89"<\'\xd5N\xa2\xdf\x03\xc0L~G\xa6\xc9/\x7f?\xbd\x94b:\x91\x96}1\x15\x12\xf7\xc6g{Rkv\x86Av\x03\x16\n\xf8p\xc2\xa33'
    elif salt == '\xeb<\x90mkfs.fat\0\x02\x01\x01\0\x01\x10\0\0\x01\xf8\x01\x00 \x00@\0\0\0\0\0\0\0\0\0\x80\x00)\xe3\xbe\xad\xdeminifat3   FAT12   \x0e\x1f':
      return '\xa3\xafQ\x1e\xcb\xb7\x1cB`\xdb\x8aW\xeb0P\xffSu}\x9c\x16\xea-\xc2\xb7\xc6\xef\xe3\x0b\xdbnJ"\xfe\x8b\xb3c=\x16\x1ds\xc2$d\xdf\x18\xf3F>\x8e\x9d\n\xda\\\x8fHk?\x9d\xe8\x02 \xcaF'
    elif salt == '\xeb<\x90mkfs.fat\x00\x02\x01\x01\x00\x01\x10\x00\x00\x01\xf8\x01\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00)\xe3\xbe\xad\xdeminifat3   FAT12   \x0e\x1f':
      return '\xb8\xe0\x11d\xfa!\x1c\xb6\xf8\xb9\x03\x05\xff\x8f\x82\x86\xcb,B\xa4\xe2\xfc,:Y2;\xbf\xc2Go\xc7n\x91\xad\xeeq\x10\x00:\x17X~st\x86\x95\nu\xdf\x0c\xbb\x9b\x02\xd7\xe8\xa6\x1d\xed\x91\x05#\x17,'
  # We could use a different hash algorithm and a different iteration count.
  header_key_size = 64
  #blocksize = 16  # For MD2
  #blocksize = 64  # For MD4, MD5, RIPEMD, SHA1, SHA224, SHA256.
  #blocksize = 128  # For SHA384, SHA512.
  sha512_blocksize = 128
  # TODO(pts): Is kernel-mode crypto (AF_ALG,
  # https://www.kernel.org/doc/html/v4.16/crypto/userspace-if.html) faster?
  # cryptsetup seems to be doing it.
  return pbkdf2(passphrase, salt, header_key_size, iterations, sha512, sha512_blocksize)


def parse_dechd(dechd):
  check_dechd(dechd)
  keytable = dechd[256 : 256 + 64]
  decrypted_size, decrypted_ofs = struct.unpack('>QQ', buffer(dechd, 100, 16))
  return keytable, decrypted_size, decrypted_ofs


def get_table(device, passphrase, device_id, pim=None, truecrypt_mode=0):
  enchd = open(device).read(512)
  if len(enchd) != 512:
    raise ValueError('Raw device too short for VeraCrypt header.')
  dechd = None
  if truecrypt_mode == 1:  # Try TrueCrypt, then VeraCrypt.
    # TODO(pts): Reuse the partial output of the smaller iterations.
    #            Unfortunately hashlib.pbkdf2_hmac doesn't support that.
    header_key = build_header_key(passphrase, enchd, pim=pim, is_truecrypt=True)  # A bit slow.
    dechd = decrypt_header(enchd, header_key)
    try:
      # enchd_suffix_size=132 is for --mkfat=... .
      check_full_dechd(dechd, enchd_suffix_size=132, is_truecrypt=True)
    except ValueError, e:
      dechd, truecrypt_mode = None, 0
  if dechd is None:
    header_key = build_header_key(passphrase, enchd, pim=pim, is_truecrypt=bool(truecrypt_mode))  # Slow for is_truecrypt=False.
    dechd = decrypt_header(enchd, header_key)
    try:
      check_full_dechd(dechd, enchd_suffix_size=132, is_truecrypt=bool(truecrypt_mode))
    except ValueError, e:
      # We may put str(e) to the debug log, if requested.
      raise ValueError('Incorrect passphrase (%s).' % str(e).rstrip('.'))
  keytable, decrypted_size, decrypted_ofs = parse_dechd(dechd)
  return build_table(keytable, decrypted_size, decrypted_ofs, device_id)


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


def build_veracrypt_header(
    decrypted_size, passphrase, enchd_prefix='', enchd_suffix='',
    decrypted_ofs=None, pim=None, fake_luks_uuid=None,
    is_truecrypt=False, keytable=None):
  """Returns 512 bytes.

  Args:
    decrypted_size: Size of the decrypted block device, this is 0x20000
        bytes smaller than the encrypted block device.
  Returns:
    enchd, the encrypted 512-byte header to be saved to the beginning
    of the raw device.
  """
  if len(enchd_prefix) > 64:
    raise ValueError('enchd_prefix too long, got: %d' % len(enchd_prefix))
  if len(enchd_suffix) > 192:
    raise ValueError('enchd_suffix too long, got: %d' % len(enchd_suffix))
  check_decrypted_size(decrypted_size)
  check_decrypted_ofs(decrypted_ofs)
  if fake_luks_uuid is not None:
    if len(fake_luks_uuid) > 36:
      raise ValueError(
          'fake_luks_uuid must be at most 36 bytes, got: %d' %
          len(fake_luks_uuid))
    fake_luks_uuid += '\0' * (36 - len(fake_luks_uuid))
    # LUKS1 header with (invalid) empty hash name.
    luks_header = 'LUKS\xba\xbe\0\1\0'
    if not luks_header.startswith(buffer(enchd_prefix, 0, len(luks_header))):
      raise ValueError('enchd_prefix value conflicts with with luks_header.')
    enchd_prefix = luks_header + enchd_prefix[len(luks_header):]
    assert len(enchd_prefix) <= 64
  salt = enchd_prefix + get_random_bytes(64 - len(enchd_prefix))
  header_key = build_header_key(passphrase, salt, pim=pim, is_truecrypt=is_truecrypt)  # Slow.
  if fake_luks_uuid is not None:
    zeros_ofs = 160  # Must be divisible by 16 for crypt_aes_xts.
    # util-linux blkid supports 40 bytes, busybox blkid supports 36 bytes.
    zeros_data = ''.join((
        get_random_bytes(8), fake_luks_uuid, '\0', get_random_bytes(3)))
    assert len(zeros_data) == 48
    zeros_data = crypt_aes_xts(
        header_key, zeros_data, do_encrypt=False, ofs=zeros_ofs - 64)
  else:
    zeros_ofs = zeros_data = None
  if keytable is None:
    keytable = get_random_bytes(64)
  check_keytable(keytable)
  sector_size = 512
  dechd = build_dechd(
      salt, keytable, decrypted_size, sector_size, decrypted_ofs=decrypted_ofs,
      zeros_ofs=zeros_ofs, zeros_data=zeros_data, is_truecrypt=is_truecrypt)
  assert len(dechd) == 512
  check_full_dechd(dechd, is_truecrypt=is_truecrypt)
  enchd = encrypt_header(dechd, header_key)
  assert len(enchd) == 512
  do_reenc = not enchd.endswith(enchd_suffix)
  if do_reenc:
    keytablep_enc = enchd[256 : -len(enchd_suffix)] + enchd_suffix
    assert keytablep_enc.endswith(enchd_suffix)
    keytablep = crypt_aes_xts(header_key, keytablep_enc, do_encrypt=False, ofs=192)
    assert crypt_aes_xts(header_key, keytablep, do_encrypt=True, ofs=192) == keytablep_enc
    dechd2 = build_dechd(
        salt, keytablep, decrypted_size, sector_size,
        decrypted_ofs=decrypted_ofs, is_truecrypt=is_truecrypt)
    check_full_dechd(dechd2, enchd_suffix_size=len(enchd_suffix), is_truecrypt=is_truecrypt)
    assert dechd2.endswith(keytablep)
    assert len(dechd2) == 512
    enchd = encrypt_header(dechd2, header_key)
    assert len(enchd) == 512
    assert enchd.endswith(keytablep_enc)
    assert enchd.endswith(enchd_suffix)
    dechd = dechd2
  assert decrypt_header(enchd, header_key) == dechd
  return enchd


def get_fat_sizes(fat_header):
  import struct
  if len(fat_header) < 64:
    raise ValueError('FAT header shorter than 64 bytes, got: %d' % len(fat_header))
  data = fat_header
  # jmp2, code0, code1 can be random.
  # oem_id, folume label and fstype ares space-padded.
  (jmp0, jmp1, jmp2, oem_id, sector_size, sectors_per_cluster,
   reserved_sector_count, fat_count, rootdir_entry_count, sector_count1,
   media_descriptor, sectors_per_fat, sectors_per_track, heads, hidden_count,
   sector_count, drive_number, bpb_signature, uuid_bin, label, fstype,
   code0, code1,
  ) = struct.unpack('<3B8sHBHBHHBHHHLLHB4s11s8s2B', data[:64])
  # uuid_bin is also serial number.
  if (sector_count1 == 0 and
      reserved_sector_count > 1 and  # fsinfo sector. Typically 32.
      rootdir_entry_count == 0 and
      sectors_per_fat == 0):
    # Also: data[82 : 90] in ('', 'FAT32   ', 'MSWIN4.0', 'MSWIN4.1').
    # FAT32 is not supported because it has more than 64 bytes of filesystem
    # headers.
    raise ValueError('FAT32 detected, but it is not supported.')
  if sector_count1:
    sector_count = sector_count1
  fstype = fstype.rstrip(' ')
  del sector_count1
  #assert 0, sorted((k, v) for k, v in locals().iteritems() if k not in ('data', 'struct'))
  if fstype not in ('FAT12', 'FAT16'):
    raise ValueError('Expected FAT12 or FAT16 filesystem, got: %r' % fstype)
  if hidden_count != 0:
    raise ValueError('Expected hidden_count=0, got: %d' % hidden_count)
  if bpb_signature != 41:
    raise ValueError('Expected bpb_signature=41, got: %d' % bpb_signature)
  if reserved_sector_count < 1:
    raise ValueError('Expected reserved_sector_count>0, got: %d' % reserved_sector_count)
  if rootdir_entry_count <= 0:
    raise ValueError('Expected rootdir_entry_count>0, got: %d' % rootdir_entry_count)
  if sectors_per_fat <= 0:
    raise ValueError('Expected sectors_per_fat>0, got: %d' % sectors_per_fat)
  if fat_count not in (1, 2):
    raise ValueError('Expected fat_count 1 or 2, got: %d' % fat_count)
  rootdir_sector_count = (rootdir_entry_count + ((sector_size >> 5) - 1)) / (sector_size >> 5)
  header_sector_count = reserved_sector_count + sectors_per_fat * fat_count + rootdir_sector_count
  if header_sector_count > sector_count:
    raise ValueError('Too few sectors in FAT filesystem, not even header sectors fit.')
  cluster_count = (sector_count - header_sector_count) / sectors_per_cluster
  if fstype == 'FAT12' and cluster_count > 4078:
    raise ValueError('cluster_count too large for FAT12: %d' % cluster_count)
  if fstype == 'FAT16' and cluster_count > 65518:
    raise ValueError('cluster_count too large for FAT16: %d' % cluster_count)
  fatfs_size, fat_count, fat_size, rootdir_size, reserved_size = sector_count * sector_size, fat_count, sectors_per_fat * sector_size, rootdir_sector_count * sector_size, reserved_sector_count * sector_size
  return fatfs_size, fat_count, fat_size, rootdir_size, reserved_size, fstype


def recommend_fat_parameters(fd_sector_count, fat_count, fstype=None, sectors_per_cluster=None):
  """fd_sector_count is sector count for FAT and data together."""
  # * A full FAT12 is: 12 512-byte sectors, 6144 bytes, 6120 used bytes, 4080 entries, 2 dummy entries followed by 4078 cluster entries, smallest value 2, largest value 4079 == 0xfef.
  #   Thus cluster_count <= 4078.
  #   Largest data size with cluster_size=512: 2087936 bytes.  dd if=/dev/zero bs=512 count=4092 of=minifat6.img && mkfs.vfat -f 1 -F 12 -i deadbee6 -n minifat6 -r 16 -s 1 minifat6.img
  #   Largest data size with cluster_size=1024: 4175872 bytes. Doing this with FAT16 cluster_size=512 would add 10240 bytes of overheader.
  #   Largest data size with cluster_size=2048: 8351744 bytes.
  #   Largest data size with cluster_size=4096: 16703488 bytes.
  # * A full FAT16 is: 256 512-byte sectors, 131072 bytes, 131040 used bytes, 65520 entries, 2 dummy entries followed by 65518 cluster entries, smallest value 2, largest value 65519 == 0xffef.
  #   Thus cluster_count <= 65518.
  #   Largest data size with cluster_size=512: 33545216 bytes (<32 MiB).  dd if=/dev/zero bs=512 count=65776 of=minifat7.img && mkfs.vfat -f 1 -F 16 -i deadbee7 -n minifat7 -r 16 -s 1 minifat7.img
  #   Largest data size with cluster_size=65536: 4293787648 bytes (<4 GiB).
  #assert 0, (fstype, sectors_per_cluster)
  if fstype is None:
    fstypes = ('FAT12', 'FAT16')
  if sectors_per_cluster is None:
    sectors_per_clusters = (1, 2, 4, 8, 16, 32, 64, 128)
  options = []
  for fstype in fstypes:
    max_cluster_count = (65518, 4078)[fstype == 'FAT12']
    # Minimum number of clusters for FAT16 is 4087 (based on:
    # https://github.com/Distrotech/mtools/blob/13058eb225d3e804c8c29a9930df0e414e75b18f/mformat.c#L222).
    # Otherwise Linux 3.13 vfat fileystem and `mtools -i mdir' both get
    # confused and assume that the filesystem is FAT12.
    min_cluster_count = (4087, 1)[fstype == 'FAT12']
    for sectors_per_cluster in sectors_per_clusters:
      if sectors_per_cluster > 2 and fstype == 'FAT12':
        continue  # Heuristic, use FAT16 instead.
      # 1 is our lower bound for fat_sector_count.
      cluster_count = (fd_sector_count - 1) / sectors_per_cluster
      while cluster_count > 0:
        if fstype == 'FAT12':
          sectors_per_fat = ((((2 + cluster_count) * 3 + 1) >> 1) + 511) >> 9
        else:
          sectors_per_fat = ((2 + (cluster_count << 1)) + 511) >> 9
        cluster_count2 = (fd_sector_count - sectors_per_fat * fat_count) / sectors_per_cluster
        if cluster_count == cluster_count2:
          break
        cluster_count = cluster_count2
      is_wasted = cluster_count - max_cluster_count > 9
      cluster_count = min(cluster_count, max_cluster_count)
      if cluster_count < min_cluster_count:
        continue
      use_data_sector_count = cluster_count * sectors_per_cluster
      use_fd_sector_count = sectors_per_fat * fat_count + use_data_sector_count
      options.append((-use_fd_sector_count, sectors_per_cluster, fstype, use_fd_sector_count, sectors_per_fat, is_wasted))
  if not options:
    raise ValueError('FAT filesystem would be too small.')
  _, sectors_per_cluster, fstype, use_fd_sector_count, sectors_per_fat, is_wasted = min(options)
  if is_wasted:
    # Typical limits: FAT12 ~2 MiB, FAT16 ~4 GiB.
    raise ValueError('FAT filesystem cannot be that large.')
  #assert 0, (fstype, sectors_per_cluster, use_fd_sector_count, sectors_per_fat)
  return fstype, sectors_per_cluster, use_fd_sector_count, sectors_per_fat


def get_random_fat_salt():
  import base64
  data = get_random_bytes(8)
  code0, code1 = ord(data[6]), ord(data[7])
  oem_id = base64.b64encode(data[:6])
  return oem_id, code0, code1


def build_fat_header(label, uuid, fatfs_size, fat_count=None, rootdir_entry_count=None, fstype=None, cluster_size=None):
  """Builds a 64-byte header for a FAT12 or FAT16 filesystem."""
  import struct
  if label is not None:
    label = label.strip()
    if len(label) > 11:
      raise ValueEror('label longer than 11, got: %d' % len(label))
    if label == 'NO NAME':
      label = None
  if label:
    label += ' ' * (11 - len(label))
  else:
    label = None
  if uuid is None:
    uuid_bin = get_random_bytes(4)
  else:
    uuid = uuid.replace('-', '').lower()
    try:
      uuid_bin = uuid.decode('hex')[::-1]
    except (TypeError, ValueError):
      raise ValueError('uuid must be hex, got: %s' % uuid)
  if len(uuid_bin) != 4:
    raise ValueError('uuid_bin must be 4 bytes, got: %s' % len(uuid_bin))
  if fat_count is None:
    fat_count = 1
  else:
    fat_count = int(fat_count)
  if fat_count not in (1, 2):
    raise ValueError('Expected fat_count 1 or 2, got: %d' % fat_count)
  if fatfs_size < 2048:
    raise ValueError('fatfs_size must be at least 2048, got: %d' % fatfs_size)
  if fatfs_size & 511:
    raise ValueError('fatfs_size must be a multiple of 512, got: %d' % fatfs_size)
  if rootdir_entry_count is None:
    if fatfs_size <= (2 << 20):
      rootdir_entry_count = 1  # Actually it will be 16.
    elif fatfs_size <= (32 << 20):
      rootdir_entry_count = fatfs_size >> 16  # 512 max.
    else:
      rootdir_entry_count = 512  # mkfs.vfat default for HDDs.
  if rootdir_entry_count <= 0:
    raise ValueError('rootdir_entry_count must be at least 1, got: %d' % rootdir_entry_count)
  if fstype is not None:
    fstype = fstype.upper()
    if fstype not in ('FAT12', 'FAT16'):
      raise ValueError('fstype must be FAT12 or FAT16, got: %r' % (fstype,))
  if cluster_size is None:
    sectors_per_cluster = None
  else:
    sectors_per_cluster = int(cluster_size) >> 9
    if sectors_per_cluster not in (1, 2, 4, 8, 16, 32, 64, 128):
      raise ValueError('cluster_size must be a power of 2: 512 ... 65536, got: %d' % cluster_size)
    cluster_size = None

  sector_size = 512
  sector_count = fatfs_size >> 9
  rootdir_entry_count = (rootdir_entry_count + 15) & ~15  # Round up.
  rootdir_sector_count = (rootdir_entry_count + ((sector_size >> 5) - 1)) / (sector_size >> 5)
  # TODO(pts): Add alignment so that first cluster starts at sectors_per_cluster
  # boundary.
  reserved_sector_count = 1  # Only the boot sector (containing fat_header).
  fd_sector_count = sector_count - reserved_sector_count - rootdir_sector_count
  fstype, sectors_per_cluster, fd_sector_count, sectors_per_fat = recommend_fat_parameters(
      fd_sector_count, fat_count, fstype, sectors_per_cluster)
  sector_count = fd_sector_count + reserved_sector_count + rootdir_sector_count
  jmp0, jmp1, jmp2 = 0xeb, 0x3c, 0x90
  oem_id = 'mkfs.fat'
  media_descriptor = 0xf8
  sectors_per_track = 1  # Was 32. 0 indicates LBA, mtools doesn't support it.
  heads = 1  # Was 64. 0 indicates LBA, mtools doesn't support it.
  hidden_count = 0
  drive_number = 0x80
  bpb_signature = 0x29
  code0, code1 = 0x0e, 0x1f
  header_sector_count = reserved_sector_count + sectors_per_fat * fat_count + rootdir_sector_count
  cluster_count, wasted_sector_count = divmod(((fatfs_size >> 9) - header_sector_count), sectors_per_cluster)
  free_size = (cluster_count * sectors_per_cluster) << 9
  if header_sector_count > sector_count:
    raise ValueError(
        'Too few sectors in FAT filesystem, not even header sectors fit, increase fatfs_size to at least %d, got: %d' %
        (header_sector_count << 9, fatfs_size))
  # For FAT filesystems it's OK that the clusters are not aligned to the
  # sectors_per_cluster boundary. However, for performance, we want to align
  # them if possible (i.e. if it would still fit to fatfs_size). We do it so
  # by making the root directory a bit larger, or, if it's too large already,
  # adding reserved sectors.
  alignment_sector_count_to_add = -header_sector_count % sectors_per_cluster
  if wasted_sector_count and alignment_sector_count_to_add <= wasted_sector_count:
    # Add the extra sectors to the root directory.
    rootdir_entry_count += alignment_sector_count_to_add << 4
    if rootdir_entry_count > 65520:
      reserved_sector_count += ((rootdir_entry_count - 65520) >> 4)
      rootdir_entry_count = 65520
  fstype += ' ' * (8 - len(fstype))
  if sector_count >> 16:
    sector_count1 = 0
  else:
    sector_count1, sector_count = sector_count, 0
  label1 = label or 'NO NAME    '
  fat_header = struct.pack(
      '<3B8sHBHBHHBHHHLLHB4s11s8s2B',
      jmp0, jmp1, jmp2, oem_id, sector_size, sectors_per_cluster,
      reserved_sector_count, fat_count, rootdir_entry_count, sector_count1,
      media_descriptor, sectors_per_fat, sectors_per_track, heads,
      hidden_count, sector_count, drive_number, bpb_signature, uuid_bin,
      label1, fstype, code0, code1)
  assert len(fat_header) == 64
  assert label is None or len(label) == 11
  return fat_header, label


def build_veracrypt_fat(decrypted_size, passphrase, do_include_all_header_sectors, fat_header=None, device_size=None, pim=None, do_randomize_salt=False, is_truecrypt=False, keytable=None, **kwargs):
  # FAT12 filesystem header based on minifat3.
  # dd if=/dev/zero bs=1K   count=64  of=minifat1.img && mkfs.vfat -f 1 -F 12 -i deadbeef -n minifat1 -r 16 -s 1 minifat1.img  # 64 KiB FAT12.
  # dd if=/dev/zero bs=512  count=342 of=minifat2.img && mkfs.vfat -f 1 -F 12 -i deadbee2 -n minifat2 -r 16 -s 1 minifat2.img  # Largest FAT12 with 1536 bytes of overhead.
  # dd if=/dev/zero bs=1024 count=128 of=minifat3.img && mkfs.vfat -f 1 -F 12 -i deadbee3 -n minifat3 -r 16 -s 1 minifat3.img  # 128 KiB FAT12.
  # dd if=/dev/zero bs=1K  count=2052 of=minifat5.img && mkfs.vfat -f 1 -F 16 -i deadbee5 -n minifat5 -r 16 -s 1 minifat5.img  # 2052 KiB FAT16.
  if fat_header is None:
    if 'fatfs_size' not in kwargs:
      if (not isinstance(device_size, (int, long)) or
          not isinstance(decrypted_size, (int, long))):
        raise ValueError('Could not infer fatfs_size, missing device_size or decrypted_size.')
      kwargs['fatfs_size'] = device_size - decrypted_size
    fat_header, label = build_fat_header(**kwargs)
  elif kwargs:
    raise ValueError('Both fat_header and FAT parameters (%s) specified.' % sorted(kwargs))
  else:
    label = None
  if len(fat_header) != 64:
    raise ValueError('fat_header must be 64 bytes, got: %d' % len(fat_header))
  if do_randomize_salt:
    oem_id, code0, code1 = get_random_fat_salt()
    fat_header = ''.join((
        '\xe9\x79\x01',  # jmp strict near boot_code, to offset 0x71c.
        oem_id, fat_header[11 : 62], chr(code0), chr(code1)))
  fatfs_size, fat_count, fat_size, rootdir_size, reserved_size, fstype = get_fat_sizes(fat_header)
  if decrypted_size is None:
    if not isinstance(device_size, (int, long)):
      raise TypeError
    decrypted_size = device_size - fatfs_size
    if decrypted_size < 512:
      raise ValueError('FAT filesystem too large, no room for encrypted volume after it.')
  if device_size is not None:
    if decrypted_size != device_size - fatfs_size:
      raise ValueError('Inconsistent device_size, decrypted_size and fatfs_size.')
    device_size = None
  enchd = build_veracrypt_header(
      decrypted_size=decrypted_size, passphrase=passphrase,
      enchd_prefix=fat_header,
      # Position-independent boot code starting at 0x17c (memory 0x7d1c) to
      # display an error message, wait for a keypress and reboot.
      # Based on fat16_boot_tvc.nasm.
      enchd_suffix='\x0e\x1f\xe8d\x00This is not a bootable disk.  Please insert a bootable floppy and\r\npress any key to try again ...\r\n\x00^\xac"\xc0t\x0bV\xb4\x0e\xbb\x07\x00\xcd\x10^\xeb\xf02\xe4\xcd\x16\xcd\x19\xeb\xfeU\xaa',
      decrypted_ofs=fatfs_size, pim=pim, is_truecrypt=is_truecrypt,
      keytable=keytable)
  assert len(enchd) == 512
  assert enchd.startswith(fat_header)
  if not do_include_all_header_sectors:
    return enchd, fatfs_size
  output = [enchd]
  output.append('\0' * (reserved_size - 512))
  if fstype == 'FAT12':
    empty_fat = '\xf8\xff\xff' + '\0' * (fat_size - 3)
  elif fstype == 'FAT16':
    empty_fat = '\xf8\xff\xff\xff' + '\0' * (fat_size - 4)
  else:
    assert 0, 'Unknown fstype: %s' % (fstype,)
  output.extend(empty_fat for _ in xrange(fat_count))
  if label:
    # Volume label in root directory.
    output.append(label)
    output.append('\x08\0\0\xa7|\x8fM\x8fM\0\0\xa7|\x8fM\0\0\0\0\0\0')
    # Rest of root directory.
    output.append('\0' * (rootdir_size - 32))
  else:
    output.append('\0' * rootdir_size)
  data = ''.join(output)
  assert len(data) == reserved_size + fat_size * fat_count + rootdir_size
  assert len(data) <= fatfs_size
  return data, fatfs_size


def parse_byte_size(size_str):
  """Returns the corresponding byte size."""
  if size_str.endswith('K'):
    return int(size_str[:-1]) << 10
  elif size_str.endswith('M'):
    return int(size_str[:-1]) << 20
  elif size_str.endswith('G'):
    return int(size_str[:-1]) << 30
  elif size_str.endswith('T'):
    return int(size_str[:-1]) << 40
  elif size_str.endswith('P'):
    return int(size_str[:-1]) << 50
  else:
    return int(size_str)


def parse_pim_arg(arg):
  value = arg[arg.find('=') + 1:]
  try:
    value = int(value)
  except ValueError:
    raise UsageError('unsupported pim value: %s' % arg)
  if value < -14:
    raise UsageError('pim must be at least -14, got: %s' % arg)
  return value


def parse_passphrase(arg):
  value = arg[arg.find('=') + 1:]
  if not value:
    raise UsageError('empty flag value: %s' % arg)
  return value


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


def run_and_read_stdout(cmd, is_dmsetup=False):
  import subprocess

  if not isinstance(cmd, (list, tuple)):
    raise TypeError
  try:
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
  except OSError, e:
    raise RuntimeError('Command %s failed to start: %s' % (cmd[0], e))
  try:
    return p.stdout.read()
  finally:
    p.stdout.close()
    if p.wait():
      if is_dmsetup:
        try:
          open('/dev/mapper/control', 'r+b').close()
        except IOError:
          raise SystemExit('command %s failed, rerun as root with sudo' % cmd[0])
      raise RuntimeError('Command %s failed with exit code %d' % (cmd[0], p.wait()))


def run_and_write_stdin(cmd, data, is_dmsetup=False):
  import subprocess

  if not isinstance(cmd, (list, tuple)):
    raise TypeError
  try:
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
  except OSError, e:
    raise RuntimeError('Command %s failed to start: %s' % (cmd[0], e))
  try:
    p.stdin.write(data)
  finally:
    p.stdin.close()
    if p.wait():
      if is_dmsetup:
        try:
          open('/dev/mapper/control', 'r+b').close()
        except IOError:
          raise SystemExit('command %s failed, rerun as root with sudo' % cmd[0])
      raise RuntimeError('Command %s failed with exit code %d' % (cmd[0], p.wait()))


def parse_device_id(device_id):
  try:
    major, minor = map(int, device_id.split(':'))
  except ValueError:
    raise ValueError('Bad device_id syntax: %r' % device_id)
  if not (1 <= major <= 255 and 0 <= minor <= 255):
    raise ValueError('Bad device_id: %r' % device_id)
  return major, minor


def yield_dm_devices():
  value = [run_and_read_stdout(('dmsetup', 'ls'), is_dmsetup=True)]
  for line in value.pop().splitlines():
    i = line.rfind('\t')
    if i < 0:
      raise ValueError('Bad dmsetup ls line: %r' % line)
    name2, dev2 = line[:i], line[i + 1:].replace(', ', ':')
    try:
      if not dev2.startswith('(') or not dev2.endswith(')'):
        raise ValueError
      device_id = dev2[1 : -1]
    except ValueError:
      raise ValueError('Bad dmsetup ls dev: %r' % dev2)
    yield name2, parse_device_id(device_id)


def setup_path_for_dmsetup():
  import os
  # For /sbin/dmsetup.
  os.environ['PATH'] = os.getenv('PATH', '/bin:/usr/bin') + ':/sbin'


def fsync_loop_device(f):
  import os
  import stat

  try:
    os.fsync
  except AttributeError:
    return
  try:
    stat_obj = os.fstat(f.fileno())
    if stat.S_ISBLK(stat_obj.st_mode) and (stat_obj.st_rdev >> 8) == 7:
      f.flush()
      os.fsync(f.fileno())
  except (OSError, IOError):
    pass


def parse_device_size_arg(arg):
  value = arg[arg.find('=') + 1:]
  if value in ('auto', 'max'):
    value = 'auto'
  else:
    try:
      value = parse_byte_size(value)
    except ValueError:
      raise UsageError('unsupported byte size value: %s' % arg)
    if value <= 0:
      raise UsageError('device size must be positive, got: %s' % arg)
    if value & 511:
      raise UsageError('device size must be a multiple of 512, got: %s' % arg)
  return value


def parse_decrypted_ofs_arg(arg):
  value = arg[arg.find('=') + 1:]
  try:
    value = parse_byte_size(value)
  except ValueError:
    raise UsageError('unsupported byte size value: %s' % arg)
  if value < 0:
    raise UsageError('offset must be nonnegative, got: %s' % arg)
  if value & 511:
    raise UsageError('offset must be a multiple of 512, got: %s' % arg)
  return value


def parse_keytable_arg(arg):
  value = arg[arg.find('=') + 1:].lower()
  if value in ('random', 'new', 'rnd'):
    value = get_random_bytes(64)
  else:
    try:
      value = value.decode('hex')
    except (TypeError, ValueError):
      raise UsageError('keytable value must be hex: %s' % arg)
  if len(value) != 64:
    raise UsageError('keytable must be 64 bytes: %s' % arg)
  return value


# ---


class UsageError(SystemExit):
  """Raised when there is a problem in the command-line."""


TEST_PASSPHRASE = 'ThisIsMyVeryLongPassphraseForMyVeraCryptVolume'
TEST_SALT = "~\xe2\xb7\xa1M\xf2\xf6b,o\\%\x08\x12\xc6'\xa1\x8e\xe9Xh\xf2\xdd\xce&\x9dd\xc3\xf3\xacx^\x88.\xe8\x1a6\xd1\xceg\xebA\xbc]A\x971\x101\x163\xac(\xafs\xcbF\x19F\x15\xcdG\xc6\xb3"


def cmd_get_table(args):
  truecrypt_mode = 1
  pim = 0
  device = passphrase = None

  i, value = 0, None
  while i < len(args):
    arg = args[i]
    if arg == '-' or not arg.startswith('-'):
      break
    i += 1
    if arg == '--':
      break
    elif arg.startswith('--pim='):
      pim = parse_pim_arg(arg)
    elif arg in '--no-truecrypt':
      truecrypt_mode = 0
    elif arg in ('--maybe-truecrypt', '--veracrypt'):  # --veracrypt compatible with `cryptsetup open' and `cryptsetup tcryptDump'.
      truecrypt_mode = 1
    elif arg == '--truecrypt':
      truecrypt_mode = 2
    elif arg.startswith('--password='):
      # Unsafe, ps(1) can read it.
      passphrase = parse_passphrase(arg)
    elif arg in ('--test-passphrase', '--test-password'):
      # With --test-passphase --salt=test it's faster, because
      # build_header_key is much faster.
      passphrase = TEST_PASSPHRASE
    else:
      raise UsageError('unknown flag: %s' % arg)
  del value  # Save memory.
  if device is None:
    if i >= len(args):
      raise UsageError('missing <device> hosting the encrypted volume')
    device = args[i]
    i += 1
  if i != len(args):
    raise UsageError('too many command-line arguments')

  if passphrase is None:
    passphrase = prompt_passphrase(do_passphrase_twice=False)

  #device_id = '7:0'
  device_id = device  # TODO(pts): Option to display major:minor.
  sys.stdout.write(get_table(device, passphrase, device_id, pim=pim, truecrypt_mode=truecrypt_mode))
  sys.stdout.flush()


def cmd_mount(args):
  # This function is Linux-only.
  import os
  import stat
  import subprocess

  is_custom_name = False
  pim = keyfiles = filesystem = hash = encryption = slot = device = passphrase = truecrypt_mode = protect_hidden = type_arg = name = None

  i, value = 0, None
  while i < len(args):
    arg = args[i]
    if arg == '-' or not arg.startswith('-'):
      break
    i += 1
    if arg == '--':
      break
    elif arg.startswith('--pim=') or arg.startswith('--veracrypt-pim='):
      pim = parse_pim_arg(arg)
      if truecrypt_mode == 2:
        truecrypt_mode = 1
    elif arg in '--no-truecrypt':
      truecrypt_mode = 0
    elif arg in ('--maybe-truecrypt', '--veracrypt'):  # --veracrypt compatible with `cryptsetup open' and `cryptsetup tcryptDump'.
      truecrypt_mode = 1
    elif arg == '--truecrypt':
      truecrypt_mode = 2
    elif arg.startswith('--password='):
      # Unsafe, ps(1) can read it.
      passphrase = parse_passphrase(arg)
    elif arg in ('--test-passphrase', '--test-password'):
      # With --test-passphase --salt=test it's faster, because
      # build_header_key is much faster.
      passphrase = TEST_PASSPHRASE
    elif arg.startswith('--keyfiles='):
      value = arg[arg.find('=') + 1:].lower().replace('-', '')
      if value != '':
        raise UsageError('unsupported flag value: %s' % arg)
      keyfiles = value
    elif arg.startswith('--protect-hidden='):
      protect_hidden = arg[arg.find('=') + 1:].lower()
    elif arg == '--custom-name':
      is_custom_name = True
    elif arg == '--no-custom-name':
      is_custom_name = False
    elif arg in ('--type', '-M') and i < len(args):
      type_arg = args[i]
      i += 1
      if type_arg != 'tcrypt':
        raise UsageError('unsupported flag value: %s' % arg)
      if truecrypt_mode is None:
        truecrypt_mode = 2  # --truecrypt.
    elif arg.startswith('--type='):
      type_arg = arg[arg.find('=') + 1:].lower()
      if type_arg != 'tcrypt':
        raise UsageError('unsupported flag value: %s' % arg)
      if truecrypt_mode is None:
        truecrypt_mode = 2  # --truecrypt.
    elif arg.startswith('--slot='):
      value = arg[arg.find('=') + 1:]
      try:
        slot = int(value)
      except ValueError:
        raise UsageError('unsupported flag value: %s' % arg)
      if slot <= 0:
        raise UsageError('slot must be positive, got: %s' % arg)
    elif arg.startswith('--encryption='):
      value = arg[arg.find('=') + 1:].lower()
      if value != 'aes':
        raise UsageError('unsupported flag value: %s' % arg)
      encryption = value
    elif arg.startswith('--hash='):
      value = arg[arg.find('=') + 1:].lower().replace('-', '')
      if value != 'sha512':
        raise UsageError('unsupported flag value: %s' % arg)
      hash = value
    elif arg.startswith('--filesystem='):
      value = arg[arg.find('=') + 1:].lower().replace('-', '')
      if value != 'none':
        raise UsageError('unsupported flag value: %s' % arg)
      filesystem = value
    elif arg.startswith('--keyfiles='):
      value = arg[arg.find('=') + 1:].lower().replace('-', '')
      if value != '':
        raise UsageError('unsupported flag value: %s' % arg)
      keyfiles = value
    elif arg.startswith('--pim='):
      pim = parse_pim_arg(arg)
    else:
      raise UsageError('unknown flag: %s' % arg)
  del value  # Save memory.
  if device is None:
    if i >= len(args):
      raise UsageError('missing <device> hosting the encrypted volume')
    device = args[i]
    i += 1
  if name is None and is_custom_name:
    if i >= len(args):
      raise UsageError('missing dmsetup table <name> for the encrypted volume')
    name = args[i]
    i += 1
    check_table_name(name)
  if i != len(args):
    raise UsageError('too many command-line arguments')
  if truecrypt_mode is None:
    truecrypt_mode = 1
  if i != len(args):
    raise UsageError('too many command-line arguments')
  if encryption != 'aes':
    raise UsageError('missing flag: --encryption=aes')
  if hash != 'sha512':
    raise UsageError('missing flag: --hash=sha512')
  if filesystem != 'none':
    raise UsageError('missing flag: --filesystem=none')
  if protect_hidden != 'no':
    raise UsageError('missing flag: --protect-hidden=no')
  if keyfiles != '':
    raise UsageError('missing flag: --keyfiles=')
  if pim is None:
    raise UsageError('missing flag --pim=..., recommended: --pim=0')
  if name is not None and slot is not None:
    raise UsageError('<name> conflicts with --slot=')

  setup_path_for_dmsetup()
  had_dmsetup = False

  if name is None:
    if slot is None:
      slots = set()
      hd_dmsetup = True
      for name2, (major, minor) in yield_dm_devices():
        if not name2.startswith('veracrypt'):
          continue
        try:
          slot2 = int(names2[8:])
        except ValueError:
          continue
        if slot2 > 0:
          slots.add(slot2)
      slot = 1
      while slot in slots:
        slot += 1
    name = 'veracrypt%d' % slot
    print >>sys.stderr, 'info: using dmsetup table name: %s' % name

  try:
    stat_obj = os.stat(device)
  except OSError, e:
    raise SystemExit('error opening raw device: %s' % e)  # Contains filename.
  losetup_cleanup_device = None
  try:
    if stat.S_ISREG(stat_obj.st_mode):  # Disk image.
      if device.startswith('-'):
        raise UsageError('raw device must not start with dash: %s' % device)
      # Alternative, without race conditions, but doesn't work with busybox:
      # sudo losetup --show -f RAWDEVICE
      data = run_and_read_stdout(('losetup', '-f'))
      if not data or data.startswith('-'):
        raise ValueError('Expected loopback device name.')
      data = data.rstrip('\n')
      if '\n' in data or not data:
        raise ValueError('Expected single loopback device name.')
      losetup_cleanup_device = data
      # TODO(pts): If cryptsetup creates the dm device, and then `dmsetup
      # remove' is run then the loop device gets deleted automatically.
      # Make the automatic deletion happen for tinyveracrypt as well.
      # Can losetup do this?
      run_and_write_stdin(('losetup', data, device), '', is_dmsetup=True)
      stat_obj = os.stat(data)
      if not stat.S_ISBLK(stat_obj.st_mode):
        raise RuntimeError('Block device expected: %s' % data)
      # Major is typically 7 for /dev/loop...
    elif not stat.S_ISBLK(stat_obj.st_mode):
      raise SystemExit('not a block device or image: %s' % device)
    device_id = '%d:%d' % (stat_obj.st_rdev >> 8, stat_obj.st_rdev & 255)

    if passphrase is None:
      if not had_dmsetup:
        yield_dm_devices()  # Get a possible error about sudo before prompting.
      passphrase = prompt_passphrase(do_passphrase_twice=False)

    table = get_table(device, passphrase, device_id, pim=pim, truecrypt_mode=truecrypt_mode)  # Slow.
    run_and_write_stdin(('dmsetup', 'create', name), table, is_dmsetup=True)
    losetup_cleanup_device = None
  finally:
    if losetup_cleanup_device is not None:
      import subprocess
      try:  # Ignore errors.
        subprocess.call(('losetup', '-d', losetup_cleanup_device))
      except OSError:
        pass


def cmd_open_table(args):
  # This function is Linux-only.
  import os
  import stat
  import subprocess

  device_size = 'auto'
  keytable = device = name = decrypted_ofs = end_ofs = None

  i, value = 0, None
  while i < len(args):
    arg = args[i]
    if arg == '-' or not arg.startswith('-'):
      break
    i += 1
    if arg == '--':
      break
    elif arg.startswith('--size='):
      device_size = parse_device_size_arg(arg)
    elif arg.startswith('--ofs='):
      value = arg[arg.find('=') + 1:]
      decrypted_ofs = parse_decrypted_ofs_arg(arg)
    elif arg.startswith('--end-ofs='):
      value = arg[arg.find('=') + 1:]
      end_ofs = parse_decrypted_ofs_arg(arg)
    elif arg.startswith('--keytable='):
      keytable = parse_keytable_arg(arg)
    else:
      raise UsageError('unknown flag: %s' % arg)
  del value  # Save memory.
  if device is None:
    if i >= len(args):
      raise UsageError('missing <device> hosting the encrypted volume')
    device = args[i]
    i += 1
  if name is None:
    if i >= len(args):
      raise UsageError('missing dmsetup table <name> for the encrypted volume')
    name = args[i]
    i += 1
    check_table_name(name)
  if i != len(args):
    raise UsageError('too many command-line arguments')
  if keytable is None:
    raise UsageError('missing flag: --keytable=...')
  if decrypted_ofs is None:
    raise UsageError('missing flag: --ofs=...')
  if end_ofs is None:
    raise UsageError('missing flag: --end-ofs=...')

  if device_size == 'auto':
    f = open(device, 'rb')
    try:
      f.seek(0, 2)
      device_size = f.tell()
    finally:
      f.close()
  if device_size < decrypted_ofs + end_ofs:
    raise UsageError('raw device too small for dmsetup table, size: %d' % device_size)

  try:
    stat_obj = os.stat(device)
  except OSError, e:
    raise SystemExit('error opening raw device: %s' % e)  # Contains filename.
  losetup_cleanup_device = None
  try:
    # !! Get rid of code duplication below with cmd_mount.
    if stat.S_ISREG(stat_obj.st_mode):  # Disk image.
      if device.startswith('-'):
        raise UsageError('raw device must not start with dash: %s' % device)
      # Alternative, without race conditions, but doesn't work with busybox:
      # sudo losetup --show -f RAWDEVICE
      data = run_and_read_stdout(('losetup', '-f'))
      if not data or data.startswith('-'):
        raise ValueError('Expected loopback device name.')
      data = data.rstrip('\n')
      if '\n' in data or not data:
        raise ValueError('Expected single loopback device name.')
      losetup_cleanup_device = data
      # TODO(pts): If cryptsetup creates the dm device, and then `dmsetup
      # remove' is run then the loop device gets deleted automatically.
      # Make the automatic deletion happen for tinyveracrypt as well.
      # Can losetup do this?
      run_and_write_stdin(('losetup', data, device), '', is_dmsetup=True)
      stat_obj = os.stat(data)
      if not stat.S_ISBLK(stat_obj.st_mode):
        raise RuntimeError('Block device expected: %s' % data)
      # Major is typically 7 for /dev/loop...
    elif not stat.S_ISBLK(stat_obj.st_mode):
      raise SystemExit('not a block device or image: %s' % device)
    device_id = '%d:%d' % (stat_obj.st_rdev >> 8, stat_obj.st_rdev & 255)

    decrypted_size = device_size - decrypted_ofs - end_ofs
    table = build_table(keytable, decrypted_size, decrypted_ofs, device_id)
    run_and_write_stdin(('dmsetup', 'create', name), table, is_dmsetup=True)
    losetup_cleanup_device = None
  finally:
    if losetup_cleanup_device is not None:
      import subprocess
      try:  # Ignore errors.
        subprocess.call(('losetup', '-d', losetup_cleanup_device))
      except OSError:
        pass


def cmd_create(args):
  is_quick = False
  do_passphrase_twice = True
  salt = ''
  is_any_luks_uuid = False
  is_truecrypt = False
  is_opened = False
  keytable = fake_luks_uuid = decrypted_ofs = fatfs_size = do_add_full_header = do_add_backup = volume_type = device = device_size = encryption = hash = filesystem = pim = keyfiles = random_source = passphrase = None
  fat_label = fat_uuid = fat_rootdir_entry_count = fat_fat_count = fat_fstype = fat_cluster_size = None

  i, value = 0, None
  while i < len(args):
    arg = args[i]
    if arg == '-' or not arg.startswith('-'):
      break
    i += 1
    if arg == '--':
      break
    elif arg.startswith('--password='):
      passphrase = parse_passphrase(arg)
    elif arg in ('--test-passphrase', '--test-password'):
      # With --test-passphase --salt=test it's faster, because
      # build_header_key is much faster.
      passphrase = TEST_PASSPHRASE
    elif arg.startswith('--keytable='):
      keytable = parse_keytable_arg(arg)
    elif arg.startswith('--salt='):
      value = arg[arg.find('=') + 1:]
      if value == 'test':
        salt = TEST_SALT
      else:
        try:
          salt = value.decode('hex')
        except (TypeError, ValueError):
          raise UsageError('salt value must be hex: %s' % arg)
      if len(salt) > 64:
        raise UsageError('salt must be at most 64 bytes: %s' % arg)
    elif arg.startswith('--fat-fstype='):
      value = arg[arg.find('=') + 1:].upper()
      if value not in ('FAT12', 'FAT16'):
        raise ValueEror('FAT fs type must be FAT12 or FAT16: %s' % arg)
      fat_fstype = value
    elif arg.startswith('--fat-label='):
      value = arg[arg.find('=') + 1:].strip()
      if len(value) > 11:
        raise ValueEror('label longer than 11: %s' % arg)
      if value == 'NO NAME' or not value:
        value = None
      fat_label = value
    elif arg.startswith('--fat-uuid'):
      value = arg[arg.find('=') + 1:].replace('-', '').lower()
      try:
        value = value.decode('hex')
      except (TypeError, ValueError):
        raise UsageError('FAT uuid must be hex: %s' % arg)
      fat_uuid = value.encode('hex')
      if len(fat_uuid) != 4:
        raise UsageError('FAT uuid must be 4 bytes: %s' % arg)
    elif arg.startswith('--fake-luks-uuid'):
      fake_luks_uuid = arg[arg.find('=') + 1:]
    elif arg == '--any-luks-uuid':
      is_any_luks_uuid = True
    elif arg == '--no-any-luks-uuid':
      is_any_luks_uuid = False
    elif arg.startswith('--fat-rootdir-entry-count='):
      value = arg[arg.find('=') + 1:]
      try:
        fat_rootdir_entry_count = int(value)
      except ValueError:
        raise UsageError('unsupported flag value: %s' % arg)
      if fat_rootdir_entry_count <= 0:
        raise UsageError('flag must be positive, got: %s' % arg)
    elif arg.startswith('--fat-cluster-size='):
      value = arg[arg.find('=') + 1:]
      try:
        fat_cluster_size = int(value)
      except ValueError:
        raise UsageError('unsupported flag value: %s' % arg)
      if (fat_cluster_size >> 9) not in (1, 2, 4, 8, 16, 32, 64, 128):
        raise UsageError('FAT cluster size must be a power of 2: 512 ... 65536: %d' % arg)
    elif arg.startswith('--fat-count='):
      value = arg[arg.find('=') + 1:]
      try:
        fat_count = int(value)
      except ValueError:
        raise UsageError('unsupported flag value: %s' % arg)
      if fat_count not in (1, 2):
        raise UsageError('FAT count must be 1 or 2, got: %s' % arg)
    elif arg.startswith('--volume-type='):
      value = arg[arg.find('=') + 1:].lower()
      if value != 'normal':
        raise UsageError('unsupported flag value: %s' % arg)
      volume_type = value
    elif arg.startswith('--encryption='):
      value = arg[arg.find('=') + 1:].lower()
      if value != 'aes':
        raise UsageError('unsupported flag value: %s' % arg)
      encryption = value
    elif arg.startswith('--hash='):
      value = arg[arg.find('=') + 1:].lower().replace('-', '')
      if value != 'sha512':
        raise UsageError('unsupported flag value: %s' % arg)
      hash = value
    elif arg.startswith('--filesystem='):
      value = arg[arg.find('=') + 1:].lower().replace('-', '')
      if value != 'none':
        raise UsageError('unsupported flag value: %s' % arg)
      filesystem = value
    elif arg.startswith('--keyfiles='):
      value = arg[arg.find('=') + 1:].lower().replace('-', '')
      if value != '':
        raise UsageError('unsupported flag value: %s' % arg)
      keyfiles = value
    elif arg.startswith('--random-source='):
      value = arg[arg.find('=') + 1:].lower().replace('-', '')
      if value != '/dev/urandom':
        raise UsageError('unsupported flag value: %s' % arg)
      random_source = value
    elif arg.startswith('--size='):
      device_size = parse_device_size_arg(arg)
    elif arg.startswith('--ofs='):
      value = arg[arg.find('=') + 1:]
      if value == 'fat':
        decrypted_ofs = value
      else:
        decrypted_ofs = parse_decrypted_ofs_arg(arg)
    elif arg.startswith('--mkfat='):
      value = arg[arg.find('=') + 1:]
      try:
        fatfs_size = parse_byte_size(value)
      except ValueError:
        raise UsageError('unsupported byte size value: %s' % arg)
      if fatfs_size < 2048:
        raise UsageError('FAT fs size must be at least 2048 bytes, got: %s' % arg)
      if fatfs_size & 511:
        raise UsageError('FAT fs size must be a multiple of 512, got: %s' % arg)
    elif arg.startswith('--pim='):
      pim = parse_pim_arg(arg)
    elif arg == '--text':
      pass  # Ignored for compatibility with the veracrypt binary.
    elif arg == '--quick':
      is_quick = True
    elif arg == '--no-quick':
      is_quick = False
    elif arg == '--add-full-header':
      do_add_full_header = True
    elif arg == '--no-add-full-header':
      do_add_full_header = False
    elif arg == '--add-backup':
      do_add_backup = True
    elif arg == '--no-add-backup':
      do_add_backup = False
    elif arg == '--opened':
      is_opened = True
    elif arg == '--no-opened':
      is_opened = False
    elif arg == '--passphrase-twice':
      do_passphrase_twice = True
    elif arg == '--passphrase-once':
      do_passphrase_twice = False
    elif arg == '--truecrypt':
      is_truecrypt = True
    elif arg in ('--no-truecrypt', '--veracrypt'):
      is_truecrypt = False
    else:
      raise UsageError('unknown flag: %s' % arg)
  del value  # Save memory.
  if device is None:
    if i >= len(args):
      raise UsageError('missing <device> hosting the encrypted volume')
    device = args[i]
    i += 1
  if i != len(args):
    raise UsageError('too many command-line arguments')
  if volume_type != 'normal':
    raise UsageError('missing flag: --volume-type=normal')
  if encryption != 'aes':
    raise UsageError('missing flag: --encryption=aes')
  if hash != 'sha512':
    raise UsageError('missing flag: --hash=sha512')
  if filesystem != 'none':
    raise UsageError('missing flag: --filesystem=none')
  if keyfiles != '':
    raise UsageError('missing flag: --keyfiles=')
  if random_source != '/dev/urandom':
    raise UsageError('missing flag: --random-source=/dev/urandm')
  if device_size is None:
    raise UsageError('missing flag: --size=...')
  if pim is None:
    if is_truecrypt:
      pim = 0
    else:
      raise UsageError('missing flag --pim=..., recommended: --pim=0')

  if is_opened:  # RAWDEVICE is a dm device pathname. Needs root access.
    # !! Add support for changing the passphrase without root.
    if decrypted_ofs is not None:
      raise UsageError('--opened conflicts with --ofs=...')
    if keytable is not None:
      raise UsageError('--opened conflicts with --keytable=...')

    import os
    import stat

    if device.startswith('/dev/mapper/'):
      name = device.split('/', 3)[3]
    else:
      stat_obj = os.stat(device)
      if stat.S_ISDIR(stat_obj.st_mode):
        major_minor = stat_obj.st_dev >> 8, stat_obj.st_dev & 255
      elif stat.S_ISBLK(stat_obj.st_mode):
        major_minor = stat_obj.st_rdev >> 8, stat_obj.st_rdev & 255
      else:
        raise UsageError(
            '--opened device must be a directory or a dm device, got: %r' %
            device)
      setup_path_for_dmsetup()
      for name2, major_minor2 in yield_dm_devices():
        if major_minor == major_minor2:
          name = name2
          break
      else:
        raise ValueError('Not a dm device: %r' % device)
    check_table_name(name)

    setup_path_for_dmsetup()
    data = run_and_read_stdout(('dmsetup', 'table', '--showkeys', name), is_dmsetup=True)
    if not data:
      raise ValueError('Empty dmsetup table.')
    data = data.rstrip('\n')
    if '\n' in data or not data:
      raise ValueError('Expected single dmsetup table line.')
    try:
      (start_sector, sector_count, target_type, sector_format, keytable,
       iv_offset, device_id, sector_offset) = data.split(' ')[:8]
      if start_sector != '0' or target_type != 'crypt':
        raise ValueError
    except ValueError:
      # Don't print data, it may contain the keytable.
      raise ValueError('Not a crypt dmsetup table line.')
    try:
      sector_count = int(sector_count)
    except ValueError:
      raise ValueError('sector_count must be an integer, got: %r' % sector_count)
    if sector_count <= 0:
      raise ValueError('sector count must be positive, got: %d' % sector_count)
    if sector_format != 'aes-xts-plain64':
      raise ValueError('sector_format must be aes-xts-plain64, got: %r' % target_type)
    try:
      keytable = keytable.decode('hex')
    except (TypeError, ValueError):
      raise ValueError('keytable must be hex, got: %s' % keytable)
    try:
      iv_offset = int(iv_offset)
    except ValueError:
      raise ValueError('iv_offset must be an integer, got: %r' % iv_offset)
    if iv_offset < 0:
      raise ValueError('sector count must be nonnegative, got: %d' % iv_offset)
    device_id = parse_device_id(device_id)  # (major, minor)
    try:
      sector_offset = int(sector_offset)
    except ValueError:
      raise ValueError('sector_offset must be an integer, got: %r' % sector_offset)
    if sector_offset < 0:
      raise ValueError('sector count must be nonnegative, got: %d' % sector_offset)
    if iv_offset != sector_offset:
      raise ValueError('offset mismatch: iv_offset=%d sector_offset=%d' % (iv_offset, sector_offset))
    device_int = device_id[0] << 8 | device_id[1]

    device = None
    for entry in sorted(os.listdir('/dev')):
      device2 = '/dev/' + entry
      try:
        stat_obj = os.stat(device2)
      except OSError, e:
        continue
      if not stat.S_ISBLK(stat_obj.st_mode):
        continue
      if stat_obj.st_rdev != device_int:
        continue
      device = device2
      break
    else:
      raise RuntimeError('Raw device %s not found in /dev.' % device_id)

    decrypted_ofs = sector_offset << 9
    if device_size == 'auto':
      do_append = True
      f = open(device, 'rb')
      try:
        f.seek(0, 2)
        device_size = f.tell()
      finally:
        f.close()
    if (device_size >> 9) < sector_offset + sector_count:
      raise ValueError('Raw device too small for encrypted volume, size: %d' % device_size)
    if (do_add_backup is None and
        (device_size >> 9) < sector_offset + sector_count + 256):
      do_add_backup = False
    if sector_offset < 256:
      do_add_full_header = False
    if fatfs_size == decrypted_ofs:
      # TODO(pts): Allow fatfs_size < decrypted_ofs.
      decrypted_ofs = None
      if do_add_full_header is None:
        do_add_full_header = True
    elif fatfs_size is not None:
      raise UsageError('--mkfat=... value conflicts with --opened, should be: %d' % decrypted_ofs)

  if fatfs_size is not None:
    if decrypted_ofs is not None:
      raise UsageError('--mkfat=... conflicts with --ofs=...')
    decrypted_ofs = 'mkfat'
  elif decrypted_ofs is None:
    decrypted_ofs = 0x20000
  if fake_luks_uuid is not None:
    if decrypted_ofs == 'fat':
      raise UsageError('--fake-luks-uuid=... conflicts with --ofs=fat')
    if decrypted_ofs == 'mkfat':
      raise UsageError('--fake-luks-uuid=... conflicts with --mkfat=...')
    if is_any_luks_uuid:
      # Any bytes can be used (not only hex), blkid recognizes them as UUID.
      if '\0' in fake_luks_uuid:
        raise UsageError('NUL not allowed in LUKS uuid: %r' % fake_luks_uuid)
      if len(fake_luks_uuid) > 36:
        raise UsageError(
            'LUKS uuid must be at most 36 bytes: %r' % fake_luks_uuid)
    else:
      if fake_luks_uuid in ('random', 'new', 'rnd'):
        fake_luks_uuid = ''
      else:
        fake_luks_uuid = fake_luks_uuid.replace('-', '').lower()
        try:
          fake_luks_uuid = fake_luks_uuid.decode('hex')
        except (TypeError, ValueError):
          raise UsageError('LUKS uuid must be hex: %s' % arg)
      if not fake_luks_uuid:
        fake_luks_uuid = get_random_bytes(16)
      if len(fake_luks_uuid) != 16:
        raise UsageError(
            'LUKS uuid must be 16 bytes, got: %d' % len(fake_luks_uuid))
      fake_luks_uuid = fake_luks_uuid.encode('hex')
      fake_luks_uuid = '-'.join((  # Add the dashes.
          fake_luks_uuid[:8], fake_luks_uuid[8 : 12], fake_luks_uuid[12 : 16],
          fake_luks_uuid[16 : 20], fake_luks_uuid[20:]))
  if do_add_full_header is None:
    do_add_full_header = decrypted_ofs not in ('fat', 'mkfat', 0)
  if do_add_backup is None:
    do_add_backup = do_add_full_header
  if do_add_backup and not do_add_full_header:
      raise UsageError('--add-backup needs --add-full-header')
  if do_add_full_header and decrypted_ofs == 'fat':
    raise UsageError('--add-backup conflicts with --ofs=fat')
  if do_add_full_header and decrypted_ofs == 0:
    raise UsageError('--add-full-header conflicts with --ofs=0')

  if device_size == 'auto' or decrypted_ofs == 'fat':
    do_append = True
    f = open(device, 'rb')
    try:
      if decrypted_ofs == 'fat':
        fat_header = f.read(64)
      if device_size == 'auto':
        f.seek(0, 2)
        device_size = f.tell()
    finally:
      f.close()
  else:
    do_append = False
  if decrypted_ofs in ('fat', 'mkfat'):
    if salt == '':
      do_randomize_salt = True
    elif salt == TEST_SALT:
      do_randomize_salt = False
    else:
      raise UsageError('specific --salt=... values conflict with --ofs=fat or --mkfat=...')
  else:
    if (do_add_full_header and
        device_size <= (decrypted_ofs << bool(do_add_backup))):
      raise UsageError('raw device too small for VeraCrypt volume, size: %d' % device_size)

  if passphrase is None:
    sys.stderr.write('warning: abort now, otherwise all data on %s will be lost\n' % device)
    passphrase = prompt_passphrase(do_passphrase_twice=do_passphrase_twice)

  if decrypted_ofs == 'fat':
    # Usage --salt=test to keep the oem_id etc. intact.
    enchd, fatfs_size = build_veracrypt_fat(
        decrypted_size=None, passphrase=passphrase, is_truecrypt=is_truecrypt,
        fat_header=fat_header, device_size=device_size, pim=pim,
        do_include_all_header_sectors=False,
        do_randomize_salt=do_randomize_salt, keytable=keytable)
    assert len(enchd) == 512
  elif decrypted_ofs == 'mkfat':
    if not do_randomize_salt:
      if fat_label is None:
        fat_label = 'minifat3'
      if fat_uuid is None:
        fat_uuid = 'DEAD-BEE3'
    enchd, fatfs_size2 = build_veracrypt_fat(
        decrypted_size=device_size - (fatfs_size << bool(do_add_backup)),
        passphrase=passphrase, do_include_all_header_sectors=True,
        label=fat_label, uuid=fat_uuid, fatfs_size=fatfs_size, fstype=fat_fstype,
        rootdir_entry_count=fat_rootdir_entry_count, fat_count=fat_fat_count,
        cluster_size=fat_cluster_size, pim=pim, do_randomize_salt=do_randomize_salt,
        keytable=keytable)
    assert 2048 <= fatfs_size2 <= fatfs_size
    assert len(enchd) >= 1536
  else:
    enchd = build_veracrypt_header(
        decrypted_size=device_size - (decrypted_ofs << bool(do_add_backup)),
        passphrase=passphrase, decrypted_ofs=decrypted_ofs,
        enchd_prefix=salt, pim=pim, fake_luks_uuid=fake_luks_uuid,
        is_truecrypt=is_truecrypt, keytable=keytable)
    assert len(enchd) == 512
  if do_add_full_header:
    if decrypted_ofs == 'mkfat':
      xofs = fatfs_size
    else:
      xofs = decrypted_ofs
    assert xofs >= len(enchd)
    enchd += get_random_bytes(xofs - len(enchd))
    assert len(enchd) == xofs
  if do_add_backup:
    if decrypted_ofs == 'mkfat':
      xofs = fatfs_size
    else:
      xofs = decrypted_ofs
    # https://www.veracrypt.fr/en/VeraCrypt%20Volume%20Format%20Specification.html
    enchd_backup = build_veracrypt_header(
        decrypted_size=device_size - (xofs << 1),
        passphrase=passphrase, decrypted_ofs=xofs,
        enchd_prefix=salt, pim=pim, is_truecrypt=is_truecrypt,
        keytable=keytable)
    enchd_backup += get_random_bytes(xofs - 512)
    assert len(enchd_backup) == xofs
  else:
    enchd_backup = ''
  if do_append:
    open(device, 'ab').close()  # Create file if needed.
  f = open(device, 'rb+')
  try:
    f.write(enchd)
    if not is_quick:
      print >>sys.stderr, 'info: overwriting device with random data'
      i = device_size - len(enchd) - len(enchd_backup)
      while i > 0:
        # TODO(pts): Generate faster random.
        data = get_random_bytes(min(i, 65536))
        f.write(data)
        i -= len(data)
      if enchd_backup:
        f.write(enchd_backup)
    elif enchd_backup:
      f.seek(device_size - len(enchd_backup))
      f.write(enchd_backup)
    try:
      f.truncate(device_size)
    except IOError:
      pass
    # This is useful so that changes in /dev/loop0 are copied back to DEVICE.img.
    fsync_loop_device(f)
  finally:
    f.close()


def main(argv):
  passphrase = TEST_PASSPHRASE
  # !! Experiment with decrypted_ofs=0, encrypted ext2 (first 0x400 bytes are arbitrary) or reiserfs/ btrfs (first 0x10000 bytes are arbitrary) filesystem,
  #    Can we have a fake non-FAT filesystem with UUID and label? For reiserfs, set_jfs_id.py would work.
  #    set_xfs_id.py doesn't work, because XFS and VeraCrypt headers conflict.
  #    LUKS (luks.c) can work, but it has UUID only (no label).
  #    No other good filesystem for ext2, see https://github.com/pts/pts-setfsid/blob/master/README.txt
  #    Maybe with bad blocks: bad block 64, and use jfs.
  #    Needs more checking, is it block 32 for jfs? mkfs.ext4 -b 1024 -l badblocks.lst ext4.img
  #    mkfs.reiserfs overwrites the first 0x10000 bytes with '\0', but then we can change it back: perl -e 'print "b"x(1<<16)' | dd bs=64K of=ext4.img conv=notrunc
  #    0x10	Has reserved GDT blocks for filesystem expansion (COMPAT_RESIZE_INODE). Requires RO_COMPAT_SPARSE_SUPER.
  #    $ python -c 'open("bigext4.img", "wb").truncate(8 << 30)'
  #    $ mkfs.ext4 -b 1024 -E nodiscard -F bigext4.img
  #    $ dumpe2fs bigext4.img >bigext4.dump
  #    Primary superblock at 1, Group descriptors at 2-33
  #    Reserved GDT blocks at 34-289  # Always 256, even for smaller filesystems.
  #    $ mkfs.ext4 -b 1024 -E nodiscard -l badblocks.lst -F bigext4.img
  #    Block 32 in primary superblock/group descriptor area bad.
  #    Blocks 1 through 34 must be good in order to build a filesystem.
  #    (So marking block 32 bad won't work for ext2, ext3, ext4 filesystems of at least about 8 GiB in size for -b 1024, or 120 GiB for -b 4096)
  #    also: Warning: the backup superblock/group descriptors at block 32768 contain bad blocks.
  #    SUXX: `fsck.ext -c ...' clears the badblocks list, so from that point on the exti{2,3,4} filesystem will be able to reuse the previous bad block
  #    There seems to be no unmovable file in ext2.
  #    btrfs (superblock at 65536) works for up to 241 GB, block size 4096, Reserved GDT blocks at 16-1024
  #    ``Reserved GDT blocks'' always finishes before 1050
  #    btrfs (superblock also at 64 MiB): To put block 32768 (64 MiB) to the ``Reserved GDT blocks'' of block group 1, we can play with `mkfs.ext4 -g ...' (blocks per block group), but it may have a performance penalty on SSDs (if not aligned to 6 MB boundary); example: python -c 'f = open("ext2.img", "wb"); f.truncate(240 << 30)' && mkfs.ext4 -E nodiscard -g 16304 -F ext2.img && dumpe2fs ext2.img >ext4.dump

  # !! use fcntl.ioctl etc. instead of dmsetup (strace on Debian Buster is helpful)
  # --- dmsetup remove:
  # grep  ' device-mapper' /proc/devices (misc?)
  # stat("/dev/mapper/control", {st_mode=S_IFCHR|0600, st_rdev=makedev(10, 236), ...}) = 0
  # open("/dev/mapper/control", O_RDWR)     = 3
  # ioctl(3, DM_VERSION, 0x21d10f0)         = 0
  # ioctl(3, DM_DEV_REMOVE, 0x21d1020)      = 0
  # !! Do we need to call udev manually to update /dev/disk/... ? (/run/udev/queue.bin)
  # !! Do we need to create the device nodes in /dev/mapper ?
  # --- dmsetup table:
  # ioctl(3, DM_VERSION, 0x13110f0)         = 0
  # ioctl(3, DM_TABLE_STATUS, 0x1311020)    = 0
  # --- dmsetup create:
  # ioctl(3, DM_DEV_CREATE, 0x146e310)      = 0
  # ioctl(3, DM_TABLE_LOAD, 0x146e240)      = 0
  # ioctl(3, DM_DEV_SUSPEND, 0x146e240)     = 0
  if len(argv) < 2:
    raise UsageError('missing command')
  if len(argv) > 1 and argv[1] == '--text':
    del argv[1]
  elif len(argv) > 2 and argv[1] == '--truecrypt' and argv[2] == '--text':
    del argv[2]
  if len(argv) > 2 and argv[1] == '--truecrypt' and argv[2] == '--create':
    argv[1 : 3] = argv[2 : 0 : -1]

  command = argv[1].lstrip('-')
  if len(argv) > 2 and command == 'get-table':  # !! Use `table' as an alias, also --showkeys.
    # !! Also add mount with compatible syntax.
    # * veracrypt --mount --text --keyfiles= --protect-hidden=no --pim=485 --filesystem=none --hash=sha512 --encryption=aes  # Creates /dev/mapper/veracrypt1
    # * cryptsetup open --type tcrypt --veracrypt /dev/sdb e4t  # Creates /dev/mapper/NAME
    # Please note that this command is not able to mount all volumes: it
    # works only with hash sha512 and encryption aes-xts-plain64, the
    # default for veracrypt-1.17, and the one the commands mkveracrypt,
    # mkinfat and mkfat generate.
    # No need to autodetect possible number of iterations (--pim=0 is good). See tcrypt_kdf in https://gitlab.com/cryptsetup/cryptsetup/blob/master/lib/tcrypt/tcrypt.c
    cmd_get_table(argv[2:])
  elif len(argv) > 2 and command == 'mount':
    # Emulates: veracrypt --text --mount --keyfiles= --protect-hidden=no --pim=0 --filesystem=none --hash=sha512 --encryption=aes RAWDEVICE
    # Difference: Doesn't mount a fuse filesystem (veracrypt needs sudo umount /tmp/.veracrypt_aux_mnt1; truecrypt needs sudo umount /tmp/.truecrypt_aux_mnt1)
    #
    # Creates /dev/mapper/veracrypt1 , use this to show the keytable: sudo dmsetup table --showkeys veracrypt1
    cmd_mount(argv[2:])
  elif len(argv) > 2 and command == 'open':
    # Emulates: cryptsetup open --type tcrypt --veracrypt RAWDEVICE NAME
    args = argv[2:]
    args[:0] = ('--keyfiles=', '--protect-hidden=no', '--pim=0',
                '--filesystem=none', '--hash=sha512', '--encryption=aes',
                '--custom-name')
    cmd_mount(args)
  elif len(argv) > 2 and command == 'open-table':
    cmd_open_table(argv[2:])
  # !! add 'close' and 'remove' (`cryptsetup close' and `dmsetup remove')
  # !! add `tcryptDump' (`cryptsetup tcryptDump')
  elif command == 'create':  # For compatibility with `veracrypt --create'.
    # Emulates: veracrypt --create --text --quick --volume-type=normal --size=104857600 --encryption=aes --hash=sha512 --filesystem=none --pim=0 --keyfiles= --random-source=/dev/urandom DEVICE.img
    # Recommended: tinyveracrypt.py --create --quick --volume-type=normal --size=auto --encryption=aes --hash=sha512 --filesystem=none --pim=0 --keyfiles= --random-source=/dev/urandom DEVICE.img
    # Difference; --quick is also respected for disk images (not only actual block devices).
    # Difference: --size=auto can be used to detect the size. (--size=... contains the value of the device size).
    # Difference: --ofs=<size>, --salt=... is not supported by veracrypt.
    # Difference: --ofs=fat (autodetecting FAT filessyem at the beginning of the device) is not supported by veracrypt.
    # Difference: --mkfat=<size>, --fat-* are not supported by veracrypt.
    # Difference: --veracrypt, --no-quick, --test-passphrase, --passphrase-once, --passphrase-twice, --no-add-full-header, --no-add-backup etc. are not supported by veracrypt.
    # Difference: --truecrypt is respected.
    # --pim=485 corresponds to iterations=500000 (https://www.veracrypt.fr/en/Header%20Key%20Derivation.html says that for --hash=sha512 iterations == 15000 + 1000 * pim).
    # For --pim=0, --pim=485 is used with --hash=sha512.
    cmd_create(argv[2:])
  elif command == 'init':  # Like create, but with better (shorter) defaults.
    # Example usage: dd if=/dev/zero of=tiny.img bs=1M count=10 && ./tinyveracrypt.py init --test-passphrase --salt=test tiny.img  # Fast.
    # Example usage: dd if=/dev/zero of=tiny.img bs=1M count=10 && ./tinyveracrypt.py init --test-passphrase --ofs=fat tiny.img
    # Example usage: dd if=/dev/zero of=tiny.img bs=1M count=30 && ./tinyveracrypt.py init --test-passphrase --mkfat=24M tiny.img  # For discard (TRIM) boundary on SSDs.
    # Example usage: dd if=/dev/zero of=tiny.img bs=1M count=10 && ./tinyveracrypt.py init --test-passphrase --salt=test --mkfat=128K tiny.img  # Fast.
    # !! Add --label=... and --uuid=... from set_jfs_id.py.
    # !! init --opened (e.g. convert from TrueCrypt to VeraCrypt) Reuse the keytable of an existing open encrypted volume (specified /dev/mapper/... or a mount point), and create a VeraCrypt header based on it. For this, flush the volume first.
    args = argv[2:]
    args[:0] = ('--quick', '--volume-type=normal', '--size=auto',
                '--encryption=aes', '--hash=sha512', '--filesystem=none',
                '--pim=0', '--keyfiles=', '--random-source=/dev/urandom',
                '--passphrase-once')
    cmd_create(args)
  else:
    raise UsageError('unknown command: %s' % command)


if __name__ == '__main__':
  try:
    sys.exit(main(sys.argv))
  except KeyboardInterrupt, e:
    try:  # Convert KeyboardInterrupt to SIGINT. Cleanups in main done.
      import os
      import signal
      os.kill
      os.getpid
      signal.signal(signal.SIGINT, signal.SIG_DFL)
    except (ImportError, OSError, AttributeError):
      raise e
    os.kill(os.getpid(), signal.SIGINT)
  except UsageError, e:
    print >>sys.stderr, 'fatal: usage: %s' % e
    sys.exit(1)
  except SystemExit, e:
    if len(e.args) == 1 and isinstance(e[0], str):
      print >>sys.stderr, 'fatal: %s' % e
      sys.exit(1)
    raise
