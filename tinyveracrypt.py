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

import itertools
import os
import os.path
import stat
import struct
import sys


def maybe_import_and_getattr(module_name, attr_name, default=None):
  try:
    __import__(module_name)
  except:
    return default
  return getattr(sys.modules[module_name], attr_name, default)


def maybe_import_and_call(module_name, func_name, args, default=None):
  try:
    __import__(module_name)
  except:
    return default
  new = getattr(sys.modules[module_name], func_name, None)
  if not callable(new):
    return default
  try:
    return new(*args)
  except ValueError:
    return None

# --- with_defaults.


def with_defaults(func__, **kwargs):
  """Returns new function object with defaults in func replace with **kwargs."""
  f = func__
  if not callable(f) or not getattr(f, 'func_code', None):
    raise TypeError
  n = f.func_code.co_argcount
  assert n >= len(f.func_defaults)
  new_defaults = []
  for i, name in enumerate(f.func_code.co_varnames[n - len(f.func_defaults) : n]):
    if name in kwargs:
      value = kwargs[name]
    else:
      value = f.func_defaults[i]
    new_defaults.append(value)
  return type(f)(f.func_code, f.func_globals, f.func_name + '@wd', tuple(new_defaults), f.func_closure)


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


# --- CRC32.


def slow_crc32(data, crc=0):
  """Returns (and takes) a signed or unsigned 32-bit integer."""
  # Based on crc32h in: http://www.hackersdelight.org/hdcodetxt/crc.c.txt
  crc, _ord = ~crc, ord
  for c in data:  # Character-by-character.
    crc ^= _ord(c)
    crc = ((crc >> 8) & 0xffffff) ^ (
       (-((crc     ) & 1) & 0x77073096) ^ (-((crc >> 1) & 1) & 0xee0e612c) ^
       (-((crc >> 2) & 1) & 0x076dc419) ^ (-((crc >> 3) & 1) & 0x0edb8832) ^
       (-((crc >> 4) & 1) & 0x1db71064) ^ (-((crc >> 5) & 1) & 0x3b6e20c8) ^
       (-((crc >> 6) & 1) & 0x76dc4190) ^ (-((crc >> 7) & 1) & 0xedb88320))
  crc = ~crc
  return (crc & 0x7fffffff) - (crc & 0x80000000)  # Sign-extend.


crc32 = maybe_import_and_getattr('zlib', 'crc32')
if not callable(crc32):
  crc32 = maybe_import_and_getattr('binascii', 'crc32')
if not callable(crc32):
  crc32 = slow_crc32


# ---  Pure Python AES block cipher.
#
# Pure Python code based on from CryptoPlus (2014-11-17): https://github.com/doegox/python-cryptoplus/commit/a5a1f8aecce4ddf476b2d80b586822d9e91eeb7d
#

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
      if len(key) not in (16, 24, 32):
        raise ValueError('Invalid AES key size: ' + str(len(key)))
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

aes_strxor_16 = make_strxor(16)


# --- AES CBC stream cipher.
#
# It is vulnerable to watermarking attacks and should be used for old
# compatible containers access only.
#

def check_aes_key(aes_key):
  if len(aes_key) not in (16, 24, 32):
    raise ValueError('aes_key must be 16, 24 or 32 bytes, got: %d' % len(aes_key))


def crypt_aes_cbc(aes_key, data, do_encrypt, iv):
  if len(data) & 15:
    raise ValueError('aes_cbc data size must be divisible by 16, got: %d' % len(data))
  if len(iv) != 16:
    raise ValueError('aes_cbc iv must be 16 bytes, got: %d' % len(iv))
  if isinstance(aes_key, str):
    check_aes_key(aes_key)
    codebook = new_aes(aes_key)
  else:
    codebook = aes_key
  do_decrypt = not do_encrypt
  codebook_crypt = (codebook.encrypt, codebook.decrypt)[do_decrypt]
  _strxor_16 = aes_strxor_16

  if do_decrypt:
    def yield_crypt_blocks(prev):
      for i in xrange(0, len(data), 16):
        prev2 = data[i : i + 16]
        yield _strxor_16(prev, codebook_crypt(prev2))
        prev = prev2
  else:
    def yield_crypt_blocks(prev):
      for i in xrange(0, len(data), 16):
        prev = codebook_crypt(_strxor_16(prev, data[i : i + 16]))
        yield prev

  return ''.join(yield_crypt_blocks(iv))


def generate_iv_plain(sector_idx, _pack=struct.pack):
  return _pack('<L12x', sector_idx & 0xffffffff)


def generate_iv_plain64(sector_idx, _pack=struct.pack):
  return _pack('<Q8x', sector_idx & 0xffffffffffffffff)


def generate_iv_plain64be(sector_idx, _pack=struct.pack):
  return _pack('>8xQ', sector_idx & 0xffffffffffffffff)


def generate_iv_essiv(sector_idx, codebook_encrypt=None, _pack=struct.pack):
  # codebook_encrypt should be overridden with a callable using with_defaults.
  # Linux drivers/md/dm-crypt.c crypt_iv_essiv_gen() also ignores the high 64 bits of sector_idx.
  return codebook_encrypt(_pack('<Q8x', sector_idx & 0xffffffffffffffff))


def get_generate_iv_func(keytable, iv_generator):
  # See https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt for the
  # differences between IV generators plain, plain64, plain64be, essiv:sha256,
  # benbi, tcw etc.
  if iv_generator == 'plain':
    return generate_iv_plain
  elif iv_generator == 'plain64':
    return generate_iv_plain64
  elif iv_generator == 'plain64be':
    return generate_iv_plain64be
  elif iv_generator == 'essiv:sha256':
    _sha256 = HASH_DIGEST_PARAMS['sha256'][0]
    codebook_encrypt = new_aes(_sha256(keytable).digest()).encrypt
    return with_defaults(generate_iv_essiv, codebook_encrypt=codebook_encrypt)
  else:
    raise ValueError('Unknown IV generator: %s' % iv_generator)


def _get_aes_cbc_sector_codebooks(keytable, iv_generator=None):
  # iv_generator should be overridden with a callable using with_defaults.
  check_aes_key(keytable)
  return new_aes(keytable), get_generate_iv_func(keytable, iv_generator)


def _crypt_aes_cbc_sectors(codebooks, data, do_encrypt, sector_idx=0):
  codebook, generate_iv_func = codebooks
  _crypt_aes_cbc = crypt_aes_cbc

  def yield_crypt_sectors(sector_idx):
    for i in xrange(0, len(data), 512):
      iv = generate_iv_func(sector_idx)
      yield _crypt_aes_cbc(codebook, buffer(data, i, 512), do_encrypt, iv)
      sector_idx += 1

  return ''.join(yield_crypt_sectors(sector_idx))


# --- AES CBC TCW (aes-cbc-tcw) seekable stream cipher.
#
# It is vulnerable to watermarking attacks and should be used for old
# compatible containers access only.
#

def check_aes_tcw_key(aes_tcw_key):
  if len(aes_tcw_key) not in (48, 56, 64):
    raise ValueError('aes_key must be 48, 56 or 64 bytes, got: %d' % len(aes_tcw_key))


def _get_aes_cbc_tcw_codebooks(aes_tcw_key):
  if isinstance(aes_tcw_key, tuple) and len(aes_tcw_key) == 3:
    return aes_tcw_key
  check_aes_tcw_key(aes_tcw_key)
  # (codebook: AES object, iv_seed: 16 bytes, whitening: 16 bytes).
  return new_aes(aes_tcw_key[:-32]), aes_tcw_key[-32 : -16], aes_tcw_key[-16:]


def crypt_aes_cbc_whitening(aes_key, data, do_encrypt, iv, whitening):
  if isinstance(aes_key, str):
    check_aes_key(aes_key)
    codebook = new_aes(aes_key)
  if len(iv) != 16:
    raise ValueError('aes_cbc_whitening iv must be 16 bytes, got: %d' % len(iv))
  if len(whitening) not in (1, 2, 4, 8, 16):
    raise ValueError('aes_cbc_whitening iv must be 1, 2, 4, 8 or 16 bytes, got: %d' % len(whitening))
  _strxor_16 = aes_strxor_16
  sw = whitening * (16 // len(whitening))

  def yield_crypt_strings():
    if do_encrypt:
      data2 = crypt_aes_cbc(codebook, data, True, iv)
      for j in xrange(0, len(data2), 16):
        yield _strxor_16(data2[j : j + 16], sw)
    else:
      data2 = ''.join(
          _strxor_16(data[j : j + 16], sw) for j in xrange(0, len(data), 16))
      yield crypt_aes_cbc(codebook, data2, False, iv)

  return ''.join(yield_crypt_strings())


def _crypt_aes_cbc_tcw_sectors(codebooks, data, do_encrypt, sector_idx=0):
  codebook, iv_seed, whitening = codebooks
  if len(data) & 15:
    raise ValueError('aes_cbc_tcw data size must be divisible by 16, got: %d' % len(data))
  pack, _strxor_16, _crc32, do_decrypt = struct.pack, aes_strxor_16, crc32, not do_encrypt

  def yield_crypt_strings(sector_idx):
    for i in xrange(0, len(data), 512):
      sector_idx_16 = pack('<QQ', sector_idx, sector_idx)
      iv = _strxor_16(iv_seed, sector_idx_16)
      sw = _strxor_16(whitening, sector_idx_16)
      sw = pack('<ll', _crc32(sw[:4]) ^ _crc32(sw[12:]), _crc32(sw[4 : 8]) ^ _crc32(sw[8 : 12])) * 2
      sector_idx += 1
      if do_decrypt:
        sector = buffer(data, i, 512)
        sector = ''.join(
            _strxor_16(sector[j : j + 16], sw) for j in xrange(0, len(sector), 16))
        yield crypt_aes_cbc(codebook, sector, False, iv)
      else:
        sector = crypt_aes_cbc(codebook, buffer(data, i, 512), True, iv)
        # assert not len(sector) & 15  # Because it's the output of crypt_aes_cbc.
        for j in xrange(0, len(sector), 16):
          yield _strxor_16(sector[j : j + 16], sw)

  return ''.join(yield_crypt_strings(sector_idx))


# --- AES LRW seekable stream cipher.


def gf2pow128mul(a, b):
  """Multiplication in GF(2**128), as polynomial multiplcation."""
  if a < b:  # Make b the smaller.
    a, b = b, a
  if b < 0:
    raise ValueError('GF(2**128) factor must be positive.')
  if a >> 128:
    raise ValueError('GF(2**128) factor too large: 0x%x' % a)
  result = 0
  while b:
    if b & 1:
      result ^= a
    b >>= 1
    a <<= 1
    if a >= 0x100000000000000000000000000000000:  # (1 << 128).
      a ^=  0x100000000000000000000000000000087
  return result


def check_aes_lrw_key(aes_lrw_key):
  if len(aes_lrw_key) not in (32, 40, 48):
    raise ValueError('aes_lrw_key must be 32, 40 or 48 bytes, got: %d' % len(aes_lrw_key))


def get_aes_lrw_codebooks(aes_lrw_key):
  if isinstance(aes_lrw_key, tuple) and len(aes_lrw_key) >= 2:
    return aes_lrw_key
  check_aes_lrw_key(aes_lrw_key)
  hi, lo = struct.unpack('>QQ', aes_lrw_key[-16:])
  return (new_aes(aes_lrw_key[:-16]), hi << 64 | lo)


def crypt_aes_lrw(aes_lrw_key, data, do_encrypt, ofs=None, block_idx=1):
  if len(data) & 15:
    raise ValueError('data size must be divisible by 16, got: %d' % len(data))
  codebook, lrw_key = get_aes_lrw_codebooks(aes_lrw_key)[:2]
  if block_idx < 0:
    raise ValueError('block_idx must be nonnegative, got: %d' % block_idx)
  if ofs is not None:
    if ofs & 15:
      raise ValueError('ofs must be divisible by 16, got: %d' % ofs)
    if ofs < -16:
      raise ValueError('ofs must be at least -16, got: %d' % ofs)
    block_idx += ofs >> 4
  is_small_block_idx = not (block_idx + (len(data) >> 4)) >> 128
  codebook_crypt = (codebook.encrypt, codebook.decrypt)[not do_encrypt]
  _gf2pow128mul, pack, _strxor_16 = gf2pow128mul, struct.pack, aes_strxor_16

  if is_small_block_idx:
    def yield_crypt_blocks(block_idx):
      for i in xrange(0, len(data), 16):
        # TODO(pts): Faster implementation (like table in Linux).
        p = _gf2pow128mul(lrw_key, block_idx)
        block_idx += 1
        ps = pack('>QQ', p >> 64, p & 0xffffffffffffffff)
        yield _strxor_16(codebook_crypt(_strxor_16(data[i : i + 16], ps)), ps)
  else:
    def yield_crypt_blocks(block_idx):
      for i in xrange(0, len(data), 16):
        p = _gf2pow128mul(lrw_key, block_idx & 0xffffffffffffffffffffffffffffffff)
        block_idx += 1
        ps = pack('>QQ', p >> 64, p & 0xffffffffffffffff)
        yield _strxor_16(codebook_crypt(_strxor_16(data[i : i + 16], ps)), ps)

  return ''.join(yield_crypt_blocks(block_idx))


def generate_lrw_iv_benbi(sector_idx):
  return ((sector_idx << 5) + 1) & 0xffffffffffffffff


def generate_lrw_iv_plain(sector_idx, _pack=struct.pack, _unpack=struct.unpack):
  return _unpack('<Q', _pack('>Q', sector_idx & 0xffffffff))[0] << 64


def generate_lrw_iv_plain64(sector_idx, _pack=struct.pack, _unpack=struct.unpack):
  return _unpack('<Q', _pack('>Q', sector_idx & 0xffffffffffffffff))[0] << 64


def generate_lrw_iv_plain64be(sector_idx):
  return sector_idx & 0xffffffffffffffff


def generate_lrw_iv_essiv(sector_idx, codebook_encrypt=None, _pack=struct.pack, _unpack=struct.unpack):
  hi, lo = _unpack('>QQ', codebook_encrypt(_pack('<Q8x', sector_idx & 0xffffffffffffffff)))
  return lo | hi << 64


def get_generate_lrw_iv_func(keytable, iv_generator):
  if iv_generator == 'benbi':  # Original design, use.
    return generate_lrw_iv_benbi
  elif iv_generator == 'plain':  # Weird, too short, don't use.
    return generate_lrw_iv_plain
  elif iv_generator == 'plain64':  # Weird, don't use.
    return generate_lrw_iv_plain64
  elif iv_generator == 'plain64be':  # Weird, don't use.
    return generate_lrw_iv_plain64be
  elif iv_generator == 'essiv:sha256':  # Weird dm-crypt, slow, don't use.
    _sha256 = HASH_DIGEST_PARAMS['sha256'][0]
    codebook_encrypt = new_aes(_sha256(keytable).digest()).encrypt
    return with_defaults(generate_lrw_iv_essiv, codebook_encrypt=codebook_encrypt)
  else:
    raise ValueError('Unknown IV generator: %s' % iv_generator)


def _get_aes_lrw_sector_codebooks(keytable, iv_generator=None):
  # iv_generator should be overridden with a callable using with_defaults.
  check_aes_lrw_key(keytable)
  return get_aes_lrw_codebooks(keytable) + (get_generate_lrw_iv_func(keytable, iv_generator),)


def _crypt_aes_lrw_sectors(codebooks, data, do_encrypt, sector_idx=0):
  generate_iv_func, _crypt_aes_lrw = codebooks[2], crypt_aes_lrw

  def yield_crypt_sectors(sector_idx):
    for i in xrange(0, len(data), 512):
      yield _crypt_aes_lrw(codebooks, buffer(data, i, 512), do_encrypt, block_idx=generate_iv_func(sector_idx))
      sector_idx += 1

  return ''.join(yield_crypt_sectors(sector_idx))


# --- AES XTS seekable stream cipher.


def check_aes_xts_key(aes_xts_key):
  if len(aes_xts_key) not in (32, 48, 64):
    raise ValueError('aes_xts_key must be 32, 48 or 64 bytes, got: %d' % len(aes_xts_key))


def get_aes_xts_codebooks(aes_xts_key):
  """Returns (codebook1, codebook2) pair, as AES objects with
  .encrypt and .decrypt methods."""
  if isinstance(aes_xts_key, tuple) and len(aes_xts_key) >= 2:
    return aes_xts_key
  check_aes_xts_key(aes_xts_key)
  half_key_size = len(aes_xts_key) >> 1
  return (new_aes(aes_xts_key[:half_key_size]),
          new_aes(aes_xts_key[half_key_size:]))


# We use pure Python code (from CryptoPlus) for AES XTS encryption. This is
# slow, but it's not a problem, because we have to encrypt only 512 bytes
# per run. Please note that pycrypto-2.6.1 (released on 2013-10-17) and
# other C crypto libraries with Python bindings don't support AES XTS.
def crypt_aes_xts(aes_xts_key, data, do_encrypt, ofs=0, sector_idx=0, iv=None):
  if len(data) < 16 and len(data) > 0:
    # AES XTS is explicity not defined for 1..15 bytes of input, see
    # `assert(N >= AES_BLK_BYTES)' in IEEE P1619/D16
    # (http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf).
    raise ValueError('At least one block of 128 bits needs to be supplied.')
  if len(data) >> 27:
    raise ValueError('data too long.')  # This is an implementation limitation.
  if ofs:
    if ofs & 15:
      raise ValueError('ofs must be divisible by 16, got: %d' % ofs)
    if ofs < 0:
      raise ValueError('ofs must be nonnegative, got: %d' % ofs)
  pack, do_decrypt, _strxor_16 = struct.pack, not do_encrypt, aes_strxor_16
  if iv is None:
    if sector_idx < 0:
      raise ValueError('sector_idx must be nonnegative, got: %d' % ofs)
    # sector_idx is LSB-first for aes-xts-plain64, see
    # https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt
    iv = pack('<QQ', sector_idx & 0xffffffffffffffff, sector_idx >> 64)
  else:
    if sector_idx:
      raise ValueError('sector_idx conflicts with iv')
  if not data:
    if not isinstance(aes_xts_key, tuple):
      check_aes_xts_key(aes_xts_key)
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

  codebook1, codebook2 = get_aes_xts_codebooks(aes_xts_key)[:2]
  codebook1_crypt = (codebook1.encrypt, codebook1.decrypt)[do_decrypt]
  del codebook1

  t0, t1 = struct.unpack('<QQ', codebook2.encrypt(iv))
  t = (t1 << 64) | t0
  for i in xrange(ofs >> 4):
    t <<= 1
    if t >= 0x100000000000000000000000000000000:  # (1 << 128).
      t ^=  0x100000000000000000000000000000087

  def yield_crypt_blocks(t):
    for i in xrange(0, len(data) - 31, 16):
      # Alternative which is 3.85 times slower: t_str = ('%032x' % t).decode('hex')[::-1]
      t_str = struct.pack('<QQ', t & 0xffffffffffffffff, t >> 64)
      yield _strxor_16(t_str, codebook1_crypt(_strxor_16(t_str, data[i : i + 16])))
      t <<= 1
      if t >= 0x100000000000000000000000000000000:
        t ^=  0x100000000000000000000000000000087

    lm15 = len(data) & 15
    if lm15:  # Process last 2 blocks if len is not divisible by 16 bytes.
      i, t0, t1 = len(data) & ~15, t, t << 1
      if t1 >= 0x100000000000000000000000000000000:
        t1 ^=  0x100000000000000000000000000000087
      if do_decrypt:
        t0, t1 = t1, t0
      t_str = struct.pack('<QQ', t0 & 0xffffffffffffffff, t0 >> 64)
      pp = _strxor_16(t_str, codebook1_crypt(_strxor_16(t_str, data[i - 16 : i])))
      t_str = struct.pack('<QQ', t1 & 0xffffffffffffffff, t1 >> 64)
      yield _strxor_16(t_str, codebook1_crypt(_strxor_16(t_str, data[i:] + pp[lm15:])))
      yield pp[:lm15]
    else:
      t_str = struct.pack('<QQ', t & 0xffffffffffffffff, t >> 64)
      yield _strxor_16(t_str, codebook1_crypt(_strxor_16(t_str, data[-16:])))

  # TODO(pts): Use even less memory by using an array.array('B', ...).
  return ''.join(yield_crypt_blocks(t))


def _get_aes_xts_sector_codebooks(keytable, iv_generator=None):
  # iv_generator should be overridden with a callable using with_defaults.
  return get_aes_xts_codebooks(keytable) + (get_generate_iv_func(keytable, iv_generator),)


def _crypt_aes_xts_sectors(codebooks, data, do_encrypt, sector_idx=0):
  generate_iv_func, _crypt_aes_xts = codebooks[2], crypt_aes_xts

  def yield_crypt_sectors(sector_idx):
    for i in xrange(0, len(data), 512):
      yield _crypt_aes_xts(codebooks, buffer(data, i, 512), do_encrypt, iv=generate_iv_func(sector_idx))
      sector_idx += 1

  return ''.join(yield_crypt_sectors(sector_idx))


# --- SHA-512 hash (message digest).


def _sha512_rotr64(x, y):
  return ((x >> y) | (x << (64 - y))) & 0xffffffffffffffff


_sha512_k = (
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817)


def slow_sha512_process(chunk, hh, _izip=itertools.izip, _rotr64=_sha512_rotr64, _k=_sha512_k):
  w = [0] * 80
  w[:16] = struct.unpack('>16Q', chunk)
  for i in xrange(16, 80):
    w[i] = (w[i - 16] + (_rotr64(w[i - 15], 1) ^ _rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)) + w[i - 7] + (_rotr64(w[i - 2], 19) ^ _rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6))) & 0xffffffffffffffff
  a, b, c, d, e, f, g, h = hh
  for i in xrange(80):
    t1 = h + (_rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)) + ((e & f) ^ ((~e) & g)) + _k[i] + w[i]
    t2 = (_rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c))
    a, b, c, d, e, f, g, h = (t1 + t2) & 0xffffffffffffffff, a, b, c, (d + t1) & 0xffffffffffffffff, e, f, g
  return [(x + y) & 0xffffffffffffffff for x, y in _izip(hh, (a, b, c, d, e, f, g, h))]


del _sha512_rotr64, _sha512_k  # Unpollute namespace.


# Fallback pure Python implementation of SHA-512 based on
# https://github.com/thomdixon/pysha2/blob/master/sha2/sha512.py
# It is about 400 times slower than OpenSSL's C implementation.
#
# This is used in Python 2.4 by default. (Python 2.5 already has
# hashlib.sha512.)
#
# Most users shouldn't be using this, because it's too slow in production
# (as used in pbkdf2). Python 2.4 users are encouraged to upgrade to
# Python >=2.5, install hashlib or pycrypto from PyPi, all of which
# contain a faster SHA-512 implementation in C.
class SlowSha512(object):
  _h0 = (0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
         0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179)

  blocksize = 1
  block_size = 128
  digest_size = 64

  __slots__ = ('_buffer', '_counter', '_h')

  def __init__(self, m=None):
    self._buffer = ''
    self._counter = 0
    self._h = self._h0
    if m is not None:
      self.update(m)

  def update(self, m):
    if not isinstance(m, (str, buffer)):
      raise TypeError('update() argument 1 must be string, not %s' % (type(m).__name__))
    if not m:
      return
    buf = self._buffer
    lb, lm = len(buf), len(m)
    self._counter += lm
    self._buffer = None
    if lb + lm < 128:
      buf += str(m)
      self._buffer = buf
    else:
      hh, i, _buffer = self._h, 0, buffer
      if lb:
        assert lb < 128
        i = 128 - lb
        hh = slow_sha512_process(buf + m[:i], hh)
      for i in xrange(i, lm - 127, 128):
        hh = slow_sha512_process(_buffer(m, i, 128), hh)
      self._h = hh
      self._buffer = m[lm - ((lm - i) & 127):]

  def digest(self):
    c = self._counter
    if (c & 127) < 112:
      return struct.pack('>8Q', *slow_sha512_process(self._buffer + struct.pack('>c%dxQ' % (119 - (c & 127)), '\x80', c << 3), self._h))
    else:
      return struct.pack('>8Q', *slow_sha512_process(struct.pack('>120xQ', c << 3), slow_sha512_process(self._buffer + struct.pack('>c%dx' % (~c & 127), '\x80'), self._h)))

  def hexdigest(self):
    return self.digest().encode('hex')

  def copy(self):
    other = type(self)()
    other._buffer = self._buffer
    other._counter = self._counter
    other._h = self._h
    return other


# --- SHA-256 hash (message digest).


def _sha256_rotr32(x, y):
  return ((x >> y) | (x << (32 - y))) & 0xffffffff


_sha256_k = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)


def slow_sha256_process(chunk, hh, _izip=itertools.izip, _rotr32=_sha256_rotr32, _k=_sha256_k):
  w = [0] * 64
  w[:16] = struct.unpack('>16L', chunk)
  for i in xrange(16, 64):
    w[i] = (w[i - 16] + (_rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)) + w[i - 7] + (_rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10))) & 0xffffffff
  a, b, c, d, e, f, g, h = hh
  for i in xrange(64):
    t1 = h + (_rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)) + ((e & f) ^ ((~e) & g)) + _k[i] + w[i]
    t2 = (_rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))
    a, b, c, d, e, f, g, h = (t1 + t2) & 0xffffffff, a, b, c, (d + t1) & 0xffffffff, e, f, g
  return [(x + y) & 0xffffffff for x, y in _izip(hh, (a, b, c, d, e, f, g, h))]


del _sha256_rotr32, _sha256_k  # Unpollute namespace.


# Fallback pure Python implementation of SHA-256 based on
# https://github.com/thomdixon/pysha2/blob/master/sha2/sha256.py
# It is about 400+ times slower than OpenSSL's C implementation.
#
# This is used in Python 2.4 by default. (Python 2.5 already has
# hashlib.sha256.)
#
# Most users shouldn't be using this, because it's too slow in production
# (as used in pbkdf2). Python 2.4 users are encouraged to upgrade to
# Python >=2.5, install hashlib or pycrypto from PyPi, all of which
# contain a faster SHA-256 implementation in C.
class SlowSha256(object):
  _h0 = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

  blocksize = 1
  block_size = 64
  digest_size = 32

  __slots__ = ('_buffer', '_counter', '_h')

  def __init__(self, m=None):
    self._buffer = ''
    self._counter = 0
    self._h = self._h0
    if m is not None:
      self.update(m)

  def update(self, m):
    if not isinstance(m, (str, buffer)):
      raise TypeError('update() argument 1 must be string, not %s' % (type(m).__name__))
    if not m:
      return
    buf = self._buffer
    lb, lm = len(buf), len(m)
    self._counter += lm
    self._buffer = None
    if lb + lm < 64:
      buf += str(m)
      self._buffer = buf
    else:
      hh, i, _buffer = self._h, 0, buffer
      if lb:
        assert lb < 64
        i = 64 - lb
        hh = slow_sha256_process(buf + m[:i], hh)
      for i in xrange(i, lm - 63, 64):
        hh = slow_sha256_process(_buffer(m, i, 64), hh)
      self._h = hh
      self._buffer = m[lm - ((lm - i) & 63):]

  def digest(self):
    c = self._counter
    if (c & 63) < 56:
      return struct.pack('>8L', *slow_sha256_process(self._buffer + struct.pack('>c%dxQ' % (55 - (c & 63)), '\x80', c << 3), self._h))
    else:
      return struct.pack('>8L', *slow_sha256_process(struct.pack('>56xQ', c << 3), slow_sha256_process(self._buffer + struct.pack('>c%dx' % (~c & 63), '\x80'), self._h)))

  def hexdigest(self):
    return self.digest().encode('hex')

  def copy(self):
    other = type(self)()
    other._buffer = self._buffer
    other._counter = self._counter
    other._h = self._h
    return other


# --- SHA-1 hash (message digest).


def _sha1_rotl32(x, y):
  return ((x << y) | (x >> (32 - y))) & 0xffffffff


def slow_sha1_process(chunk, hh, _izip=itertools.izip, _rotl=_sha1_rotl32):
  w = [0] * 80
  w[:16] = struct.unpack('>16L', chunk)
  for i in xrange(16, 80):
    w[i] = _rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
  a, b, c, d, e = hh
  for i in xrange(0, 20):
    f = (b & c) | ((~b) & d)
    a, b, c, d, e = (_rotl(a, 5) + f + e + 0x5a827999 + w[i]) & 0xffffffff, a, _rotl(b, 30), c, d
  for i in xrange(20, 40):
    f = b ^ c ^ d
    a, b, c, d, e = (_rotl(a, 5) + f + e + 0x6ed9eba1 + w[i]) & 0xffffffff, a, _rotl(b, 30), c, d
  for i in xrange(40, 60):
    f = (b & c) | (b & d) | (c & d)
    a, b, c, d, e = (_rotl(a, 5) + f + e + 0x8f1bbcdc + w[i]) & 0xffffffff, a, _rotl(b, 30), c, d
  for i in xrange(60, 80):
    f = b ^ c ^ d
    a, b, c, d, e = (_rotl(a, 5) + f + e + 0xca62c1d6 + w[i]) & 0xffffffff, a, _rotl(b, 30), c, d
  return [(x + y) & 0xffffffff for x, y in _izip(hh, (a, b, c, d, e))]


del _sha1_rotl32  # Unpollute namespace.


# Fallback pure Python implementation of SHA-1 based on
# https://codereview.stackexchange.com/a/37669
# It is about 162 times slower than OpenSSL's C implementation.
#
# Most users shouldn't be using this, because it's too slow in production
# (as used in pbkdf2). Even Python 2.4 has sha.sha (autodetected below),
# and Python >=2.5 has hashlib.sha1 (also autodetected below), so most
# users don't need this implementation.
class SlowSha1(object):
  _h0 = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)

  blocksize = 1
  block_size = 64
  digest_size = 20

  __slots__ = ('_buffer', '_counter', '_h')

  def __init__(self, m=None):
    self._buffer = ''
    self._counter = 0
    self._h = self._h0
    if m is not None:
      self.update(m)

  def update(self, m):
    if not isinstance(m, (str, buffer)):
      raise TypeError('update() argument 1 must be string, not %s' % (type(m).__name__))
    if not m:
      return
    buf = self._buffer
    lb, lm = len(buf), len(m)
    self._counter += lm
    self._buffer = None
    if lb + lm < 64:
      buf += str(m)
      self._buffer = buf
    else:
      hh, i, _buffer = self._h, 0, buffer
      if lb:
        assert lb < 64
        i = 64 - lb
        hh = slow_sha1_process(buf + m[:i], hh)
      for i in xrange(i, lm - 63, 64):
        hh = slow_sha1_process(_buffer(m, i, 64), hh)
      self._h = hh
      self._buffer = m[lm - ((lm - i) & 63):]

  def digest(self):
    c = self._counter
    if (c & 63) < 56:
      return struct.pack('>5L', *slow_sha1_process(self._buffer + struct.pack('>c%dxQ' % (55 - (c & 63)), '\x80', c << 3), self._h))
    else:
      return struct.pack('>5L', *slow_sha1_process(struct.pack('>56xQ', c << 3), slow_sha1_process(self._buffer + struct.pack('>c%dx' % (~c & 63), '\x80'), self._h)))

  def hexdigest(self):
    return self.digest().encode('hex')

  def copy(self):
    other = type(self)()
    other._buffer = self._buffer
    other._counter = self._counter
    other._h = self._h
    return other


# --- RIPEMD-160 hash (message digest).


def _ripemd160_rotl32(x, y):
  x &= 0xffffffff
  return (x << y) | (x >> (32 - y))


def slow_ripemd160_process(
    chunk, hh, _rotl32=_ripemd160_rotl32,
    _rstu0=((0, 11, 5, 8), (1, 14, 14, 9), (2, 15, 7, 9), (3, 12, 0, 11), (4, 5, 9, 13), (5, 8, 2, 15), (6, 7, 11, 15), (7, 9, 4, 5), (8, 11, 13, 7), (9, 13, 6, 7), (10, 14, 15, 8), (11, 15, 8, 11), (12, 6, 1, 14), (13, 7, 10, 14), (14, 9, 3, 12), (15, 8, 12, 6)),
    _rstu1=((7, 7, 6, 9), (4, 6, 11, 13), (13, 8, 3, 15), (1, 13, 7, 7), (10, 11, 0, 12), (6, 9, 13, 8), (15, 7, 5, 9), (3, 15, 10, 11), (12, 7, 14, 7), (0, 12, 15, 7), (9, 15, 8, 12), (5, 9, 12, 7), (2, 11, 4, 6), (14, 7, 9, 15), (11, 13, 1, 13), (8, 12, 2, 11)),
    _rstu2=((3, 11, 15, 9), (10, 13, 5, 7), (14, 6, 1, 15), (4, 7, 3, 11), (9, 14, 7, 8), (15, 9, 14, 6), (8, 13, 6, 6), (1, 15, 9, 14), (2, 14, 11, 12), (7, 8, 8, 13), (0, 13, 12, 5), (6, 6, 2, 14), (13, 5, 10, 13), (11, 12, 0, 13), (5, 7, 4, 7), (12, 5, 13, 5)),
    _rstu3=((1, 11, 8, 15), (9, 12, 6, 5), (11, 14, 4, 8), (10, 15, 1, 11), (0, 14, 3, 14), (8, 15, 11, 14), (12, 9, 15, 6), (4, 8, 0, 14), (13, 9, 5, 6), (3, 14, 12, 9), (7, 5, 2, 12), (15, 6, 13, 9), (14, 8, 9, 12), (5, 6, 7, 5), (6, 5, 10, 15), (2, 12, 14, 8)),
    _rstu4=((4, 9, 12, 8), (0, 15, 15, 5), (5, 5, 10, 12), (9, 11, 4, 9), (7, 6, 1, 12), (12, 8, 5, 5), (2, 13, 8, 14), (10, 12, 7, 6), (14, 5, 6, 8), (1, 12, 2, 13), (3, 13, 13, 6), (8, 14, 14, 5), (11, 11, 0, 15), (6, 8, 3, 13), (15, 5, 9, 11), (13, 6, 11, 11))):
  x = struct.unpack("<16L", chunk)
  a, b, c, d, e = f, g, h, i, j = hh
  for r, s, t, u in _rstu0:
    a, b, c, d, e, f, g, h, i, j = e, _rotl32((a + (b ^ c ^ d) + x[r]), s) + e, b, _rotl32(c, 10), d, j, _rotl32((f + (g ^ (h | ~i)) + x[t] + 1352829926), u) + j, g, _rotl32(h, 10), i
  for r, s, t, u in _rstu1:
    a, b, c, d, e, f, g, h, i, j = e, _rotl32((a + ((b & c) | (~b & d)) + x[r] + 1518500249), s) + e, b, _rotl32(c, 10), d, j, _rotl32((f + ((g & i) | (h & ~i)) + x[t] + 1548603684), u) + j, g, _rotl32(h, 10), i
  for r, s, t, u in _rstu2:
    a, b, c, d, e, f, g, h, i, j = e, _rotl32((a + ((b | ~c) ^ d) + x[r] + 1859775393), s) + e, b, _rotl32(c, 10), d, j, _rotl32((f + ((g | ~h) ^ i) + x[t] + 1836072691), u) + j, g, _rotl32(h, 10), i
  for r, s, t, u in _rstu3:
    a, b, c, d, e, f, g, h, i, j = e, _rotl32((a + ((b & d) | (c & ~d)) + x[r] + 2400959708), s) + e, b, _rotl32(c, 10), d, j, _rotl32((f + ((g & h) | (~g & i)) + x[t] + 2053994217), u) + j, g, _rotl32(h, 10), i
  for r, s, t, u in _rstu4:
    a, b, c, d, e, f, g, h, i, j = e, _rotl32((a + (b ^ (c | ~d)) + x[r] + 2840853838), s) + e, b, _rotl32(c, 10), d, j, _rotl32((f + (g ^ h ^ i) + x[t]), u) + j, g, _rotl32(h, 10), i
  return (hh[1] + c + i) & 0xffffffff, (hh[2] + d + j) & 0xffffffff, (hh[3] + e + f) & 0xffffffff, (hh[4] + a + g) & 0xffffffff, (hh[0] + b + h) & 0xffffffff


del _ripemd160_rotl32  # Unpollute namespace.


# Fallback pure Python implementation of RIPEMD-160 based on
# https://github.com/dlitz/pycrypto/blob/1660c692982b01741176047eefa53d794f8a81bc/Hash/RIPEMD160.py
# It is about 400+ times slower than OpenSSL's C implementation.
#
# This is used in Python 2.4 by default. (Python 2.5 already has
# hashlib.sha256.)
#
# Most users shouldn't be using this, because it's too slow in production
# (as used in pbkdf2). Python 2.4 users are encouraged to upgrade to
# Python >=2.5, install hashlib or pycrypto from PyPi, all of which
# contain a faster RIPEMD-160 implementation in C.
class SlowRipeMd160(object):
  _h0 = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)

  blocksize = 1
  block_size = 64
  digest_size = 20

  __slots__ = ('_buffer', '_counter', '_h')

  def __init__(self, m=None):
    self._buffer = ''
    self._counter = 0
    self._h = self._h0
    if m is not None:
      self.update(m)

  def update(self, m):
    if not isinstance(m, (str, buffer)):
      raise TypeError('update() argument 1 must be string, not %s' % (type(m).__name__))
    if not m:
      return
    buf = self._buffer
    lb, lm = len(buf), len(m)
    self._counter += lm
    self._buffer = None
    if lb + lm < 64:
      buf += str(m)
      self._buffer = buf
    else:
      hh, i, _buffer = self._h, 0, buffer
      if lb:
        assert lb < 64
        i = 64 - lb
        hh = slow_ripemd160_process(buf + m[:i], hh)
      for i in xrange(i, lm - 63, 64):
        hh = slow_ripemd160_process(_buffer(m, i, 64), hh)
      self._h = hh
      self._buffer = m[lm - ((lm - i) & 63):]

  def digest(self):
    c = self._counter
    # Merkle-Damgard strengthening, per RFC 1320.
    if (c & 63) < 56:
      return struct.pack('<5L', *slow_ripemd160_process(self._buffer + struct.pack('<c%dxQ' % (55 - (c & 63)), '\x80', c << 3), self._h))
    else:
      return struct.pack('<5L', *slow_ripemd160_process(struct.pack('<56xQ', c << 3), slow_ripemd160_process(self._buffer + struct.pack('<c%dx' % (~c & 63), '\x80'), self._h)))

  def hexdigest(self):
    return self.digest().encode('hex')

  def copy(self):
    other = type(self)()
    other._buffer = self._buffer
    other._counter = self._counter
    other._h = self._h
    return other


# --- Built-in hashes.


def maybe_hashlib_get_digest_cons(hash):
  try:
    hashlib = __import__('hashlib')
  except ImportError:
    return None
  digest_cons = getattr(hashlib, hash, None)
  if callable(digest_cons):
    return digest_cons
  try:
    hashlib.new(hash).digest
  except (ValueError, AttributeError):
    return None
  f = lambda string='', _hash=hash: __import__('hashlib').new(_hash, string)
  closure = None
  return type(f)(f.func_code, f.func_globals, hash, f.func_defaults, closure)


def find_best_digest_cons(hash, pycrypto_name, default=None):
  """Returns the best constructor function for the given hash."""
  if maybe_import_and_call('_hashlib', 'openssl_' + hash, ()):  # Fastest.
    return getattr(__import__('_hashlib'), 'openssl_' + hash)
  elif maybe_import_and_call('_hashlib', 'new', (hash,)):
    return maybe_hashlib_get_digest_cons(hash)
  elif maybe_import_and_call('Crypto.Hash._' + pycrypto_name, 'new', ()):
    # Crypto.Hash._SHA512 is faster than Crypto.Hash.SHA512.SHA512Hash.
    f = lambda string='', _hash=sys.modules['Crypto.Hash._' + pycrypto_name].new: _hash(string)
  elif maybe_import_and_call('hashlib', 'new', (hash,)):
    return maybe_hashlib_get_digest_cons(hash)
  elif hash == 'sha1' and maybe_import_and_call('sha', 'sha', ()):  # Python 2.4.
    f = lambda string='', _hash=sys.modules['sha'].sha: _hash(string)
  else:
    #raise ImportError(
    #    'Cannot find SHA-512 implementation: install hashlib or pycrypto, '
    #    'or upgrade to Python >=2.5.')
    return default
  closure = None
  # Ensure that __name__ can be extracted from the result, for the hash_name
  # argument of hashlib.pbkdf2_hmac.
  return type(f)(f.func_code, f.func_globals, hash, f.func_defaults, closure)


HASH_DIGEST_PARAMS = {  # {hash: (digest_cons, digest_blocksize)}.
    'sha1': (find_best_digest_cons('sha1', 'SHA1', SlowSha1), 64),
    'sha256': (find_best_digest_cons('sha256', 'SHA256', SlowSha256), 64),
    'sha224': (find_best_digest_cons('sha224', 'SHA224', None), 64),
    'sha384': (find_best_digest_cons('sha384', 'SHA384', None), 128),
    'sha512': (find_best_digest_cons('sha512', 'SHA512', SlowSha512), 128),
    'ripemd160': (find_best_digest_cons('ripemd160', 'RIPEMD160', SlowRipeMd160), 64),
}


def get_hash_digest_params(hash):
  """Returns (digest_cons, digest_blocksize)."""
  hash2 = hash.lower().replace('-', '')
  #blocksize = 16  # For MD2
  #blocksize = 64  # For MD4, MD5, RIPEMD, SHA1, SHA224, SHA256.
  #blocksize = 128  # For SHA384, SHA512.
  result = HASH_DIGEST_PARAMS.get(hash2)
  if result is None:
    raise ValueError('Unknown hash: %s' % hash)
  if result[0] is None:
    raise ValueError('Unsupported hash: %s' % hash)
  return result


def is_hash_supported(hash):
  hash2 = hash.lower().replace('-', '')
  return HASH_DIGEST_PARAMS.get(hash2, (None,))[0] is not None



# --- PBKDF2.

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


# Faster than `import pbkdf2' (available on pypi) or `import
# Crypto.Protocol.KDF', because of less indirection.
def slow_pbkdf2(passphrase, salt, size, iterations, digest_cons, blocksize):
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
  if digest_cons.__name__.startswith('Slow') and iterations > 10:
    # TODO(pts): Also show this earlier, before asking for a passphrase.
    sys.stderr.write('warning: running %d iterations of PBKDF2 using a very slow hash implementation, it may take hours; install a newer Python or hashlib to speed it up\n' % iterations)
  elif iterations > 2000:
    sys.stderr.write('warning: running %d iterations of PBKDF2 using a slow PBKDF2 implementation, it may take minutes; install a newer Python 2.7 with hashlib.pbkdf2_hmac or a newer hashlib to speed it up\n' % iterations)
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


pbkdf2 = slow_pbkdf2
try:
  if ((maybe_import_and_getattr('hashlib', 'sha512') or (lambda x: 0)).__name__.startswith('openssl_') and
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
      try:
        hashlib.new(hash_name).digest()
      except ValueError:
        # Fallback if digest_cons isn't supported by hashlib.
        return slow_pbkdf2(passphrase, salt, size, iterations, digest_cons, blocksize)
      return hashlib.pbkdf2_hmac(hash_name, passphrase, salt, iterations, size)
except ImportError:
  pass


# --- Creating loopback devices (with losetup(8) etc.).


def _get_losetup_add_linux():
  import sys
  if not sys.platform.startswith('linux'):
    raise ImportError('Linux-specific ioctls not supported.')
  import errno
  import fcntl
  import os
  import stat
  import struct
  if not callable(getattr(fcntl, 'ioctl', None)):
    raise ImportError('No function fcntl.ioctl.')
  if getattr(errno, 'EBUSY', None) != 16:
    raise ImportError('Missing EBUSY.')

  def open_device(filename, flag, mode, rdev):
    """Opens a device node, creating it if necessary. Needs root."""

    if not (stat.S_ISBLK(mode) or stat.S_ISCHR(mode)):
      raise ValueError('Device mode expected.')
    try:
      fd = os.open(filename, flag & ~os.O_CREAT)
    except OSError, e:
      if e[0] == errno.EACCES:
        raise SystemExit('opening %s has permission denied, rerun as root with sudo' % filename)
      if e[0] != errno.ENOENT:
        raise
      try:
        os.mknod(filename, mode, rdev)
      except OSError, e:
        if e[0] == errno.EACCES:
          raise SystemExit('creating device %s has permission denied, rerun as root with sudo' % filename)
        raise
      fd = os.open(filename, flag & ~os.O_CREAT)
    close_fd = fd
    try:
      stat_obj = os.fstat(fd)
      if stat.S_ISBLK(mode) and not stat.S_ISBLK(stat_obj.st_mode):
        raise RuntimeError('Block device expected: %s' % filename)
      if stat.S_ISCHR(mode) and not stat.S_ISCHR(stat_obj.st_mode):
        raise RuntimeError('Character device expected: %s' % filename)
      if stat_obj.st_rdev != rdev:
        raise RuntimeError('Expected rdev 0x%x, got 0x%x: %s' %
                           (rdev, stat_obj.st_rdev, filename))
      close_fd = None
      return fd
    finally:
      if close_fd is not None:
        os.close(fd)

  LOOP_CTL_GET_FREE      = 0x4c82
  LOOP_SET_FD            = 0x4c00
  LOOP_CLR_FD            = 0x4c01
  LOOP_SET_STATUS        = 0x4c02
  LOOP_GET_STATUS        = 0x4c03
  LOOP_CONTROL_RDEV = 0xaed
  LOOP_BASE_RDEV = 0x700
  LO_FLAGS_AUTOCLEAR = 4
  # (struct loop_info).lo_flags
  # This works on Linux i386 and Linux amd64.
  # TODO(pts): Is this architecture-dependent?
  LO_FLAGS_PACKFMT = '=44xL120x'

  def _losetup_add_linux(fd):
    # Equivalent to `losetup /dev/loop/... ...', but sets flag
    # LO_FLAGS_AUTOCLEAR so that after a `dmsetup remove' the loopback device
    # is also removed, no need to run `losetup -d /dev/loop...'.

    for _ in range(16):  # Retry a few times in case of race conditions.
      loop_fd = open_device('/dev/loop-control', os.O_RDWR, stat.S_IFCHR | 0600, LOOP_CONTROL_RDEV)
      try:
        i = fcntl.ioctl(loop_fd, LOOP_CTL_GET_FREE)
      finally:
        os.close(loop_fd)
      if i & ~255:
        raise ValueError('Bad loop device index from LOOP_CTL_GET_FREE: %d' % i)
      loop_filename = '/dev/loop%d' % i
      loop_fd = open_device(loop_filename, os.O_RDWR, stat.S_IFBLK | 0600, LOOP_BASE_RDEV + i)
      is_loop_fd_ok = False
      try:
        try:
          fcntl.ioctl(loop_fd, LOOP_SET_FD, fd)
        except (OSError, IOError), e:
          if e[0] != errno.EBUSY:
            raise
          continue
        is_ok = False
        try:
          b = struct.pack(LO_FLAGS_PACKFMT, LO_FLAGS_AUTOCLEAR)
          fcntl.ioctl(loop_fd, LOOP_SET_STATUS, b)
          is_ok = is_loop_fd_ok = True
          return loop_filename, loop_fd, None
        finally:
          if not is_ok:
            fcntl.ioctl(loop_fd, LOOP_CLR_FD, fd)
      finally:
        if not is_loop_fd_ok:
          os.close(loop_fd)
    raise RuntimeError('Couldn\'t get loop device after many retries.')

  return _losetup_add_linux


try:
  _losetup_add_linux = _get_losetup_add_linux()
except ImportError:
  _losetup_add_linux = None
del _get_losetup_add_linux


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


def run_and_write_stdin(cmd, data, is_dmsetup=False, do_show_failure=True, retry_count=0, retry_interval=1):
  import subprocess
  import time

  if not isinstance(cmd, (list, tuple)):
    raise TypeError

  had_retry = False
  while 1:
    try:
      p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    except OSError, e:
      # Don't retry this.
      raise RuntimeError('Command %s failed to start: %s' % (cmd[0], e))
    try:
      p.stdin.write(data)
    finally:
      p.stdin.close()
      exit_code = p.wait()
      if exit_code and do_show_failure and retry_count <= 0:
        if is_dmsetup:
          try:
            open('/dev/mapper/control', 'r+b').close()
          except IOError:
            raise SystemExit('command %s failed, rerun as root with sudo' % cmd[0])
        raise RuntimeError('Command %s failed with exit code %d' % (cmd[0], exit_code))
    if not exit_code or retry_count <= 0:
      if had_retry:
        print >>sys.stderr, 'info: command %s succeeded after retry' % cmd[0]
      return exit_code or 0
    retry_count -= 1
    had_retry = True
    time.sleep(retry_interval)


def run_command(cmd):
  import subprocess

  if not isinstance(cmd, (list, tuple)):
    raise TypeError
  try:
    p = subprocess.Popen(cmd)
  except OSError, e:
    raise RuntimeError('Command %s failed to start: %s' % (cmd[0], e))
  if p.wait():
    raise RuntimeError('Command %s failed with exit code %d' % (cmd[0], p.wait()))


def _losetup_add_cmd(filename):
  # This function can't set the flag LO_FLAGS_AUTOCLEAR, so after `dmsetup
  # remove', a manual run of `losetup -d' will be needed.

  if filename.startswith('-'):
    raise UsageError('raw device must not start with dash: %s' % filename)
  # Alternative, without race conditions, but doesn't work with busybox:
  # sudo losetup --show -f RAWDEVICE
  data = run_and_read_stdout(('losetup', '-f'))
  if not data or data.startswith('-'):
    raise ValueError('Expected loopback device name.')
  loop_filename = data.rstrip('\n')
  if '\n' in loop_filename or not loop_filename:
    raise ValueError('Expected single loopback device name.')
  # TODO(pts): If cryptsetup creates the dm-crypt device, and then `dmsetup
  # remove' is run then the loop device gets deleted automatically.
  # Make the automatic deletion happen for tinyveracrypt as well.
  # Can losetup do this?
  run_and_read_stdout(('losetup', loop_filename, filename), is_dmsetup=True)
  losetup_cleanup_device = loop_filename
  try:
    fd = os.open(loop_filename, os.O_RDWR)
    stat_obj = os.fstat(fd)
    # Major is typically 7 for /dev/loop...
    if not stat.S_ISBLK(stat_obj.st_mode):
      raise RuntimeError('Block device expected from losetup: %s' % loop_filename)
    losetup_cleanup_device = None
    return loop_filename, fd, loop_filename
  finally:
    if losetup_cleanup_device is not None:
      import subprocess
      try:  # Ignore errors.
        subprocess.call(('losetup', '-d', losetup_cleanup_device))
      except OSError:
        pass


def losetup_maybe_add(filename):
  """Creates a loopback device (block device) if needed.

  Args:
    filename: Name of an existing file or block device.
  Returns:
    If filename is a block device, opens for read-write, and returns
    (filename, fd, ...). Otherwise it creates a loopback device (by ioctl(2) or
    losetup(8)), opens it and returns ('/dev/loop...', fd, ...).
    The result[2] is losetup_cleanup_device which is None or containing a
    '/dev/loop/...' filename for `losetup -d' during manual cleanup.
  """
  fd = os.open(filename, os.O_RDWR)
  is_fd_ok = False
  try:
    stat_obj = os.fstat(fd)
    if stat.S_ISBLK(stat_obj.st_mode):
      is_fd_ok = True
      return filename, fd, None  # It's already a block device, no need to create a loopback device.
    if not stat.S_ISREG(stat_obj.st_mode):
      raise SystemExit('not a block device or image: %s' % filename)
    if _losetup_add_linux:
      return _losetup_add_linux(fd)
    return _losetup_add_cmd(filename)
  finally:
    if not is_fd_ok:
      os.close(fd)


def ensure_block_device(filename, block_device_callback):
  """Creates loopback block device if needed, calls block_device_callback,
  cleans up (removes the loopback block device) on failure.

  Will call block_device_callback(block_device, fd, device_id).
  """
  try:
    stat_obj = os.stat(filename)
  except OSError, e:
    raise SystemExit('error opening raw device: %s' % e)  # Contains filename.
  block_device, fd, losetup_cleanup_device = losetup_maybe_add(filename)
  try:
    stat_obj = os.fstat(fd)
    assert stat.S_ISBLK(stat_obj.st_mode)
    device_id = '%d:%d' % (stat_obj.st_rdev >> 8, stat_obj.st_rdev & 255)
    block_device_callback(block_device, fd, device_id)
    losetup_cleanup_device = None
  finally:
    os.close(fd)
    if losetup_cleanup_device is not None:
      import subprocess
      try:  # Ignore errors.
        subprocess.call(('losetup', '-d', losetup_cleanup_device))
      except OSError:
        pass


# --- VeraCrypt crypto.


def get_crypt_sectors_funcs(cipher, keytable_size=None):
  cipher = cipher.lower()
  crypt_func = None
  if cipher.startswith('aes-'):
    iv_generator = cipher[cipher.rfind('-') + 1:]
    if cipher in ('aes-xts-essiv:sha256', 'aes-xts-plain', 'aes-xts-plain64', 'aes-xts-plain64be'):
      crypt_func, get_codebooks_func, keytable_sizes = _crypt_aes_xts_sectors, with_defaults(_get_aes_xts_sector_codebooks, iv_generator=iv_generator), (32, 48, 64)
    elif cipher in ('aes-cbc-essiv:sha256', 'aes-cbc-plain', 'aes-cbc-plain64', 'aes-cbc-plain64be'):
      crypt_func, get_codebooks_func, keytable_sizes = _crypt_aes_cbc_sectors, with_defaults(_get_aes_cbc_sector_codebooks, iv_generator=iv_generator), (16, 24, 32)
    elif cipher in ('aes-lrw-benbi', 'aes-lrw-essiv:sha256', 'aes-lrw-plain', 'aes-lrw-plain64', 'aes-lrw-plain64be'):
      crypt_func, get_codebooks_func, keytable_sizes = _crypt_aes_lrw_sectors, with_defaults(_get_aes_lrw_sector_codebooks, iv_generator=iv_generator), (32, 40, 48)
    elif cipher == 'aes-cbc-tcw':
      crypt_func, get_codebooks_func, keytable_sizes = _crypt_aes_cbc_tcw_sectors, _get_aes_cbc_tcw_codebooks, (48, 56, 64)
  if not crypt_func:
    raise ValueError('Unsupported cipher: %s' % cipher)
  if keytable_size is not None and keytable_size not in keytable_sizes:
    raise ValueError('keytable_size must be any of %s for cipher %s, got: %d' %
                     (', '.join(map(str, keytable_sizes)), cipher, keytable_size))
  return crypt_func, get_codebooks_func


def check_veracrypt_keytable(keytable):
  # Not the same as check_as_xts_key, this is strict 64 bytes.
  if len(keytable) != 64:
    raise ValueError('keytable must be 64 bytes, got: %d' % len(keytable))


def check_veracrypt_keytable_or_keytablep(keytable):
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
    raise ValueError('decrypted_ofs must be nonnegative, got: %d' % decrypted_ofs)
  if decrypted_ofs & 511:
    raise ValueError('decrypted_ofs must be a multiple of 512, got: %d' % decrypted_ofs)

def check_decrypted_size(decrypted_size):
  # !! min_decrypted_size = 36 << 10  # Enforced by VeraCrypt. Can veracrypt --mount smaller ones?
  if decrypted_size & 511:
    raise ValueError('decrypted_size must be a multiple of 512, got: %d' % decrypted_size)
  if decrypted_size <= 0:
    raise ValueError('decrypted_size must be positive, got: %d' % decrypted_size)


def check_table_name(name):
  if '/' in name or '\0' in name or not name or name.startswith('-'):
    raise UsageError('invalid dmsetup table name: %r' % name)
  if name == 'control':
    raise UsageError('disallowed dmsetup table name: %r' % name)


# Position-independent boot code starting at boot sector offset 0x17c
# (memory 0x7d1c) to display an error message, wait for a keypress and
# reboot. Based on fat16_boot_tvc.nasm.
FAT_NO_BOOT_CODE = '\x0e\x1f\xe8d\x00This is not a bootable disk.  Please insert a bootable floppy and\r\npress any key to try again ...\r\n\x00^\xac"\xc0t\x0bV\xb4\x0e\xbb\x07\x00\xcd\x10^\xeb\xf02\xe4\xcd\x16\xcd\x19\xeb\xfeU\xaa'

assert len(FAT_NO_BOOT_CODE) == 132


def build_dechd(
    salt, keytable, decrypted_size, sector_size, decrypted_ofs=None,
    zeros_data=None, zeros_ofs=None, is_truecrypt=False):
  # See tech_info.txt for the TrueCrypt and VeraCrypt header formats.
  #
  # We can overlap the returned header with FAT12 and FAT16. FAT12 and FAT16
  # filesystem headers fit into our salt. See 'mkfat'.
  #
  # We can't overlap the returned header with XFS (e.g. set_xfs_id.py),
  # because XFS filesystem headers conflict with this header (decrypted_size
  # vs xfs.sectsize, byte_offset_for_key vs xfs.label, sector_size vs
  # xfs.icount, flag_bits vs xfs.blocklog etc.).
  check_veracrypt_keytable_or_keytablep(keytable)
  check_decrypted_size(decrypted_size)
  check_salt(salt)
  check_sector_size(sector_size)
  check_decrypted_size(decrypted_size)
  if decrypted_ofs is None:
    decrypted_ofs = 0x20000
  check_decrypted_ofs(decrypted_ofs)
  keytablep = keytable + '\0' * (256 - len(keytable))
  keytable = None  # Unused. keytable[:64]
  keytablep_crc32 = struct.pack('>l', crc32(keytablep))
  # Constants are based on what veracrypt-1.17 generates.
  signature = ('VERA', 'TRUE')[bool(is_truecrypt)]
  header_format_version = 5
  minimum_version_to_extract = ((1, 11), (5, 0))[bool(is_truecrypt)]
  hidden_volume_size = 0
  flag_bits = 0
  if zeros_data is not None:
    if zeros_ofs < 132 or zeros_ofs + len(zeros_data) > 252:
      raise ValueError('zeros_data and zeros_ofs in wrong interval.')
    zeros120 = ''.join(('\0' * (zeros_ofs - len(FAT_NO_BOOT_CODE)), zeros_data))
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
  header_crc32 = struct.pack('>l', crc32(header))
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
  if dechd[72 : 76] != struct.pack('>l', crc32(buffer(dechd, 256, 256))):
    raise ValueError('keytablep_crc32 mismatch.')
  if dechd[252 : 256] != struct.pack('>l', crc32(buffer(dechd, 64, 188))):
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
  decrypted_size, decrypted_ofs, encrypted_area_size = struct.unpack('>QQQ', dechd[100 : 100 + 24])
  if decrypted_size >> 50:  # Larger than 1 PB is insecure.
    raise ValueError('Volume too large.')
  if encrypted_area_size != decrypted_size:
    raise ValueError('encrypted_area_size mismatch.')
  if decrypted_ofs == 0 and signature == 'TRUE':
    # Created with old TrueCrypt.
    decrypted_ofs = 512
    decrypted_size -= 512  # Can become negative, we check it below.
  check_decrypted_size(decrypted_size)
  check_decrypted_ofs(decrypted_ofs)
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
    raise ValueError('Missing NUL padding at %d.' % len(FAT_NO_BOOT_CODE))
  if dechd[256 + 64 : 512 - ((enchd_suffix_size + 15) & ~15)].lstrip('\0'):
    # Does actual VeraCrypt check this? Does cryptsetup --veracrypt check this?
    raise ValueError('Missing NUL padding after keytable.')


def build_table(
    keytable, decrypted_size, decrypted_ofs, display_device, iv_ofs, cipher,
    do_showkeys, opt_params=('allow_discards',)):
  check_aes_xts_key(keytable)
  check_decrypted_size(decrypted_size)
  if isinstance(display_device, (list, tuple)):
    display_device = '%d:%d' % tuple(display_device)
  offset = decrypted_ofs
  start_offset_on_logical = 0
  if opt_params:
    opt_params_str = ' %d %s' % (len(opt_params), ' '.join(opt_params))
  else:
    opt_params_str = ''
  target_type = 'crypt'
  if not do_showkeys:
    keytable = '\0' * len(keytable)
  # https://www.kernel.org/doc/Documentation/device-mapper/dm-crypt.txt
  return '%d %d %s %s %s %d %s %s%s\n' % (
      start_offset_on_logical, decrypted_size >> 9, target_type,
      cipher, keytable.encode('hex'),
      iv_ofs >> 9, display_device, offset >> 9, opt_params_str)


def encrypt_header(dechd, header_key):
  check_dechd(dechd)
  check_header_key(header_key)
  enchd = dechd[:64] + crypt_aes_xts(header_key, dechd[64 : 512], do_encrypt=True)
  assert len(enchd) == 512
  return enchd


def crypt_for_veracrypt_header(cipher, key, data, do_encrypt):
  check_header_key(key)
  if cipher == 'aes-xts-plain64':
    return crypt_aes_xts(key, data, do_encrypt=do_encrypt)
  elif cipher == 'aes-lrw-benbi':
    return crypt_aes_lrw(key[32:] + key[:16], data, do_encrypt=do_encrypt)
  elif cipher == 'aes-cbc-tcw':
    # Oddly enough, crypt_aes_cbc_tcw_sectors would be incorrect here. The
    # call below (including the strange whitening value overlapping with the
    # IV) is compatible with `case CBC:' in EncryptBuffer(...) in TrueCrypt
    # 7.1a (and earlier).
    return crypt_aes_cbc_whitening(key[32:], data, do_encrypt=do_encrypt, iv=key[:16], whitening=key[8 : 16])
  else:
    raise ValueError('cipher %s not supported for TrueCrypt/VeraCrypt header encryption.' % cipher)


def decrypt_header(enchd, header_key):
  if len(enchd) != 512:
    raise ValueError('enchd must be 512 bytes, got: %d' % len(enchd))
  check_header_key(header_key)
  dechd = enchd[:64] + crypt_aes_xts(header_key, enchd[64 : 512], do_encrypt=False)
  assert len(dechd) == 512
  return dechd


def get_iterations(pim, is_truecrypt=False, hash='sha512'):
  # Calculations compatible with VeraCrypt 1.12 or later.
  if pim:  # https://www.veracrypt.fr/en/Header%20Key%20Derivation.html
    if hash in ('sha512', 'whirlpool'):
      return 15000 + 1000 * pim
    else:
      return pim << 11  # * 2048.
  elif is_truecrypt:  # Consistent with SETUP_MODES.
    if hash in ('ripemd160', 'sha1'):
      return 2000
    # TrueCrypt 5.0 SHA-512 has 1000 iterations (corresponding to --pim=-14),
    # see: https://gitlab.com/cryptsetup/cryptsetup/wikis/TrueCryptOnDiskFormat
    return 1000
  else:  # Consistent with SETUP_MODES.
    if hash == 'ripemd160':
      return 655331
    else:  # --pim=485 corresponds to iterations=500000
      return 500000


# Slow, takes about 6..60 seconds.
def build_header_key(passphrase, salt_or_enchd, pim=None, is_truecrypt=False, iterations=None, hash='sha512'):
  if len(salt_or_enchd) < 64:
    raise ValueError('Salt too short.')
  salt = salt_or_enchd[:64]
  if iterations is None:
    iterations = get_iterations(pim, is_truecrypt, hash)
  passphrase = get_passphrase_str(passphrase)  # Prompt the user late.
  # Speedup for testing.
  if hash == 'sha512' and passphrase == 'ThisIsMyVeryLongPassphraseForMyVeraCryptVolume' and iterations == 500000:
    if salt == "~\xe2\xb7\xa1M\xf2\xf6b,o\\%\x08\x12\xc6'\xa1\x8e\xe9Xh\xf2\xdd\xce&\x9dd\xc3\xf3\xacx^\x88.\xe8\x1a6\xd1\xceg\xebA\xbc]A\x971\x101\x163\xac(\xafs\xcbF\x19F\x15\xcdG\xc6\xb3":
      return '\x11Q\x91\xc5h%\xb2\xb2\xf0\xed\x1e\xaf\x12C6V\x7f+\x89"<\'\xd5N\xa2\xdf\x03\xc0L~G\xa6\xc9/\x7f?\xbd\x94b:\x91\x96}1\x15\x12\xf7\xc6g{Rkv\x86Av\x03\x16\n\xf8p\xc2\xa33', passphrase
    elif salt == '\xeb<\x90mkfs.fat\0\x02\x01\x01\0\x01\x10\0\0\x01\xf8\x01\x00 \x00@\0\0\0\0\0\0\0\0\0\x80\x00)\xe3\xbe\xad\xdeminifat3   FAT12   \x0e\x1f':
      return '\xa3\xafQ\x1e\xcb\xb7\x1cB`\xdb\x8aW\xeb0P\xffSu}\x9c\x16\xea-\xc2\xb7\xc6\xef\xe3\x0b\xdbnJ"\xfe\x8b\xb3c=\x16\x1ds\xc2$d\xdf\x18\xf3F>\x8e\x9d\n\xda\\\x8fHk?\x9d\xe8\x02 \xcaF', passphrase
    elif salt == '\xeb<\x90mkfs.fat\x00\x02\x01\x01\x00\x01\x10\x00\x00\x01\xf8\x01\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00)\xe3\xbe\xad\xdeminifat3   FAT12   \x0e\x1f':
      return '\xb8\xe0\x11d\xfa!\x1c\xb6\xf8\xb9\x03\x05\xff\x8f\x82\x86\xcb,B\xa4\xe2\xfc,:Y2;\xbf\xc2Go\xc7n\x91\xad\xeeq\x10\x00:\x17X~st\x86\x95\nu\xdf\x0c\xbb\x9b\x02\xd7\xe8\xa6\x1d\xed\x91\x05#\x17,', passphrase
  # We could use a different hash algorithm and a different iteration count.
  header_key_size = 64
  digest_cons, digest_blocksize = get_hash_digest_params(hash)
  # TODO(pts): Is kernel-mode crypto (AF_ALG,
  # https://www.kernel.org/doc/html/v4.16/crypto/userspace-if.html) faster?
  # cryptsetup seems to be using it.
  return pbkdf2(passphrase, salt, header_key_size, iterations, digest_cons, digest_blocksize), passphrase


def parse_dechd(dechd):
  check_dechd(dechd)
  keytable = dechd[256 : 256 + 64]
  decrypted_size, decrypted_ofs = struct.unpack('>QQ', buffer(dechd, 100, 16))
  if decrypted_ofs == 0 and dechd[64 : 64 + 4] == 'TRUE':
    # Created with old TrueCrypt. Emulates `truecrypt --text --mount'.
    decrypted_ofs = 512
    decrypted_size -= 512
    check_decrypted_size(decrypted_size)  # Check for negative.
  return keytable, decrypted_size, decrypted_ofs


class IncorrectPassphraseError(ValueError):
  """Raised when trying to open an encrypted volume with an incorrect
  passphrase."""


# From cryptsetup-1.7.3/lib/tcrypt/tcrypt.c .
#
# Please note that tcrypt.c tries multiple ciphers: ('aes-xts-plain64',
# 'serpent-xts-plain64', 'twofish-xts-plain64', ...) (29 in total),
# we support only the first one.
#
# cryptsetup-1.7.3 ignores is_legacy and also detects legacy modes.
SETUP_MODES = (  # (is_legacy, is_veracrypt, kdf, hash, iterations).
    (0, 0, 'pbkdf2', 'ripemd160', 2000),
    (0, 0, 'pbkdf2', 'ripemd160', 1000),
    (0, 0, 'pbkdf2', 'sha512',    1000),
    (0, 0, 'pbkdf2', 'whirlpool', 1000),
    (1, 0, 'pbkdf2', 'sha1',      2000),
    (0, 1, 'pbkdf2', 'sha512',    500000),
    (0, 1, 'pbkdf2', 'ripemd160', 655331),
    (0, 1, 'pbkdf2', 'ripemd160', 327661), # Boot only.
    (0, 1, 'pbkdf2', 'whirlpool', 500000),
    (0, 1, 'pbkdf2', 'sha256',    500000), # VeraCrypt 1.0f.
    (0, 1, 'pbkdf2', 'sha256',    200000), # Boot only.
)


def get_dechd_for_table(enchd, passphrase, pim, truecrypt_mode, hash):
  # This function doesn't support LUKS, the caller should.
  if truecrypt_mode not in (0, 1, 2):
    raise ValueError('Unknown truecrypt_mode: %r' % truecrypt_mode)
  if hash is not None and not is_hash_supported(hash):
    # We shouldn't reach this, parse_veracrypt_hash_arg(...) should have
    # caught it already.
    raise SystemExit('unsupported hash requested: %s' % hash)
  if pim is None:
    if truecrypt_mode == 0:  # VeraCrypt only.
      setup_modes = [m for m in SETUP_MODES if m[1]]
    elif truecrypt_mode == 2:  # TrueCrypt only.
      setup_modes = [m for m in SETUP_MODES if not m[1]]
    else:
      setup_modes = list(SETUP_MODES)
    if hash is not None:
      setup_modes = [m for m in setup_modes if m[3] == hash]
      if not setup_modes:
        pim = 0  # Try to get some more modes below.
    else:
      setup_modes = [m for m in setup_modes if is_hash_supported(m[3])]
      if not setup_modes:  # We shouldn't reach this.
        raise ValueError('No setup modes remaining (unexpected).')
  if pim is not None:
    setup_modes = []
    if hash is None:
      hash = 'sha512'
    if truecrypt_mode in (2, 1):  # Try TrueCrypt first.
      setup_modes.append((0, 0, 'pbkdf2', hash, get_iterations(pim, True, hash)))
    if truecrypt_mode in (0, 1):
      setup_modes.append((0, 1, 'pbkdf2', hash, get_iterations(pim, False, hash)))
  cipher = 'aes-xts-plain64'

  for is_legacy, is_veracrypt, kdf, hash, iterations in setup_modes:
    # TODO(pts): Add sha256 and ripemd160 with backup Python implementations.
    if not is_hash_supported(hash):  # We shouldn't reach this.
      raise ValueError('Hash not supported (unexpected): %s' % hash)
    if kdf != 'pbkdf2':  # Not supported by tinyveracrypt.
      continue
    # TODO(pts): Reuse the partial output of the smaller iterations.
    #            Unfortunately hashlib.pbkdf2_hmac doesn't support that.
    # Slow.
    #print (is_veracrypt, hash, iterations)
    header_key, passphrase = build_header_key(passphrase, enchd, pim=None, is_truecrypt=not is_veracrypt, iterations=iterations, hash=hash)
    dechd = decrypt_header(enchd, header_key)
    try:
      check_full_dechd(dechd, enchd_suffix_size=len(FAT_NO_BOOT_CODE), is_truecrypt=not is_veracrypt)
      return dechd, cipher
    except ValueError, e:
      # We may want to put str(e) to the debug log, if requested.
      #print str(e)
      pass
  raise IncorrectPassphraseError('Incorrect passphrase (%s).' % str(e).rstrip('.'))


def get_table(device, passphrase, device_id, pim, truecrypt_mode, hash, do_showkeys, display_device=None):
  luks_device_size = None
  f = open(device)
  try:
    enchd = f.read(512)
    if len(enchd) != 512:
      raise ValueError('Raw device too short for encrypted volume.')
    if ((pim is None and hash is None and truecrypt_mode == 1 and is_luks1(enchd)) or
        truecrypt_mode == 3):
      f.seek(0, 2)
      luks_device_size = f.tell()
      decrypted_ofs, keytable, cipher = get_open_luks_info(f, passphrase)  # Slow.
  finally:
    f.close()

  if luks_device_size is None:
    if is_luks1(enchd):
      if truecrypt_mode == 0:
        what = 'VeraCrypt'
      elif truecrypt_mode == 2:
        what = 'TrueCrypt'
      else:
        what = 'VeraCrypt/TrueCrypt'
      sys.stderr.write('warning: raw device has LUKS header, trying to open it as %s will likely fail\n' % what)
    dechd, cipher = get_dechd_for_table(enchd, passphrase, pim, truecrypt_mode, hash)  # Slow.
    keytable, decrypted_size, decrypted_ofs = parse_dechd(dechd)
    iv_ofs = decrypted_ofs
  else:
    decrypted_size = luks_device_size - decrypted_ofs
    iv_ofs = 0
  if display_device is None:
    display_device = device_id
  return build_table(keytable, decrypted_size, decrypted_ofs, display_device, iv_ofs, cipher, do_showkeys)


def get_random_bytes(size, _functions=[]):
  if size == 0:
    return ''
  if not _functions:
    def manual_random(size):
      return ''.join(chr(random.randrange(0, 255)) for _ in xrange(size))

    try:
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
    is_truecrypt=False, keytable=None, hash='sha512'):
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
    # keytable is at dechd[256 : 512 - 192], no room for >192 bytes of
    # suffix.
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
  header_key, _ = build_header_key(passphrase, salt, pim=pim, is_truecrypt=is_truecrypt, hash=hash)  # Slow.
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
  check_veracrypt_keytable(keytable)
  sector_size = 512
  dechd = build_dechd(
      salt, keytable, decrypted_size, sector_size, decrypted_ofs=decrypted_ofs,
      zeros_ofs=zeros_ofs, zeros_data=zeros_data, is_truecrypt=is_truecrypt)
  assert len(dechd) == 512
  check_full_dechd(dechd, is_truecrypt=is_truecrypt)
  enchd = encrypt_header(dechd, header_key)
  assert len(enchd) == 512
  if not enchd.endswith(enchd_suffix):
    # This is a bit complicated, because keytablep_crc32 has to be
    # recomputed in build_dechd.
    keytablep_enc = enchd[256 : -len(enchd_suffix)] + enchd_suffix
    assert len(keytablep_enc) == 256  # 2nd half of enchd.
    assert keytablep_enc.endswith(enchd_suffix)
    keytablep = crypt_aes_xts(header_key, keytablep_enc, do_encrypt=False, ofs=192)
    #assert crypt_aes_xts(header_key, keytablep, do_encrypt=True, ofs=192) == keytablep_enc
    dechd2 = build_dechd(
        salt, keytablep, decrypted_size, sector_size,
        decrypted_ofs=decrypted_ofs, is_truecrypt=is_truecrypt)
    check_full_dechd(dechd2, enchd_suffix_size=len(enchd_suffix), is_truecrypt=is_truecrypt)
    assert dechd2.endswith(keytablep)
    assert len(dechd2) == 512
    enchd = encrypt_header(dechd2, header_key)
    assert len(enchd) == 512
    assert enchd.endswith(keytablep_enc)
    #assert enchd.endswith(enchd_suffix)  # Implied from .endswith(keytablep_enc).
    dechd = dechd2
  assert enchd.startswith(enchd_prefix)
  assert decrypt_header(enchd, header_key) == dechd
  assert len(enchd) == 512
  return enchd


def get_recommended_veracrypt_decrypted_ofs(device_size, do_add_full_header):
  if device_size < (1 << 20):
    return (512, 0x20000)[bool(do_add_full_header)]  # VeraCrypt minimum, small overhead.
  device_size = min(device_size, 512 << 20)
  result = (4 << 10, 0x20000)[bool(do_add_full_header)]
  while device_size >= (result << 9):
    result <<= 1
  # At most 0.4% overhead, at most 2 MiB (default LUKS header size, >1 MiB
  # default partition alignment).
  return result


def get_fat_sizes(fat_header):
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
  label = label.lstrip(' ')
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
  rootdir_sector_count = (rootdir_entry_count + ((sector_size >> 5) - 1)) // (sector_size >> 5)
  header_sector_count = reserved_sector_count + sectors_per_fat * fat_count + rootdir_sector_count
  if header_sector_count > sector_count:
    raise ValueError('Too few sectors in FAT filesystem, not even header sectors fit.')
  cluster_count = (sector_count - header_sector_count) // sectors_per_cluster
  if fstype == 'FAT12' and cluster_count > 4078:
    raise ValueError('cluster_count too large for FAT12: %d' % cluster_count)
  if fstype == 'FAT16' and cluster_count > 65518:
    raise ValueError('cluster_count too large for FAT16: %d' % cluster_count)
  fatfs_size, fat_count, fat_size, rootdir_size, reserved_size = sector_count * sector_size, fat_count, sectors_per_fat * sector_size, rootdir_sector_count * sector_size, reserved_sector_count * sector_size
  return fatfs_size, fat_count, fat_size, rootdir_size, reserved_size, fstype, label


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
      cluster_count = (fd_sector_count - 1) // sectors_per_cluster
      while cluster_count > 0:
        if fstype == 'FAT12':
          sectors_per_fat = ((((2 + cluster_count) * 3 + 1) >> 1) + 511) >> 9
        else:
          sectors_per_fat = ((2 + (cluster_count << 1)) + 511) >> 9
        cluster_count2 = (fd_sector_count - sectors_per_fat * fat_count) // sectors_per_cluster
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


def build_fat_header(label, uuid, fatfs_size, fat_count=None, rootdir_entry_count=None, fstype=None, cluster_size=None, boot_code_size=None, do_randomize_salt=False):
  """Builds a 64-byte header for a FAT12 or FAT16 filesystem."""
  # FAT12 filesystem header based on minifat3.
  # dd if=/dev/zero bs=1K   count=64  of=minifat1.img && mkfs.vfat -f 1 -F 12 -i deadbeef -n minifat1 -r 16 -s 1 minifat1.img  # 64 KiB FAT12.
  # dd if=/dev/zero bs=512  count=342 of=minifat2.img && mkfs.vfat -f 1 -F 12 -i deadbee2 -n minifat2 -r 16 -s 1 minifat2.img  # Largest FAT12 with 1536 bytes of overhead.
  # dd if=/dev/zero bs=1024 count=128 of=minifat3.img && mkfs.vfat -f 1 -F 12 -i deadbee3 -n minifat3 -r 16 -s 1 minifat3.img  # 128 KiB FAT12.
  # dd if=/dev/zero bs=1K  count=2052 of=minifat5.img && mkfs.vfat -f 1 -F 16 -i deadbee5 -n minifat5 -r 16 -s 1 minifat5.img  # 2052 KiB FAT16.
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
  rootdir_sector_count = (rootdir_entry_count + ((sector_size >> 5) - 1)) // (sector_size >> 5)
  # TODO(pts): Add alignment so that first cluster starts at sectors_per_cluster
  # boundary.
  reserved_sector_count = 1  # Only the boot sector (containing fat_header).
  fd_sector_count = sector_count - reserved_sector_count - rootdir_sector_count
  fstype, sectors_per_cluster, fd_sector_count, sectors_per_fat = recommend_fat_parameters(
      fd_sector_count, fat_count, fstype, sectors_per_cluster)
  sector_count = fd_sector_count + reserved_sector_count + rootdir_sector_count
  if boot_code_size is None:
    jmp_data = '\xeb\x3c\x90'  # Smallest `jmp near' jump to offset 62.
  else:  # Position-independent boot code at end of boot sector.
    if not 3 <= boot_code_size <= 512 - 64:
      raise ValueError('boot_code size out of range, got: %d' % boot_code_size)
    jmp_data = struct.pack('<BH', 0xe9, (512 - 3) - boot_code_size)  # jmp strict near boot_code.
  media_descriptor = 0xf8
  sectors_per_track = 1  # Was 32. 0 indicates LBA, mtools doesn't support it.
  heads = 1  # Was 64. 0 indicates LBA, mtools doesn't support it.
  hidden_count = 0
  drive_number = 0x80
  bpb_signature = 0x29
  if do_randomize_salt:
    oem_id, code0, code1 = get_random_fat_salt()
  else:
    oem_id, code0, code1 = 'mkfs.fat', 0x0e, 0x1f
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
      '<3s8sHBHBHHBHHHLLHB4s11s8s2B',
      jmp_data, oem_id, sector_size, sectors_per_cluster,
      reserved_sector_count, fat_count, rootdir_entry_count, sector_count1,
      media_descriptor, sectors_per_fat, sectors_per_track, heads,
      hidden_count, sector_count, drive_number, bpb_signature, uuid_bin,
      label1, fstype, code0, code1)
  assert len(fat_header) == 64
  assert label is None or len(label) == 11
  return fat_header


def build_fat_boot_sector(fat_header, boot_code):
  if boot_code is None:
    boot_code = boot_code  # Must be position-independent.
  if len(fat_header) + len(boot_code) > 512:
    raise ValueError('fat_header and boot_code too long.')
  return ''.join((
      struct.pack('<BH', 0xe9, (512 - 3) - len(boot_code)),  # jmp strict near boot_code
      fat_header[3 : 512 - len(boot_code)],
      '\0' * (512 - len(fat_header) - len(boot_code)),
      boot_code))


def check_fat_boot_sector(boot_sector_data):
  if len(boot_sector_data) != 512:
    raise ValueError('boot_sector_data must be 512 bytes, got: %d' % len(boot_sector_data))
  if boot_sector_data[0] not in '\xe9\xeb':
    # TODO(pts): Check the jump offset as well.
    raise ValueError('Bad jump instruction in FAT header.')
  if boot_sector_data[510 : 512] != 'U\xaa':
    raise ValueError('FAT boot sector signature not found.')


def build_empty_fat(fat_header, boot_sector_data=None):
  fatfs_size, fat_count, fat_size, rootdir_size, reserved_size, fstype, label = get_fat_sizes(fat_header)
  if boot_sector_data:
    pass
  elif len(fat_header) < 512:
    boot_sector_data = build_fat_boot_sector(fat_header, FAT_NO_BOOT_CODE)
  else:
    boot_sector_data = fat_header
  check_fat_boot_sector(boot_sector_data)
  output = [boot_sector_data]
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
  return data


def randomize_fat_header(fat_header):
  if len(fat_header) < 62:
    raise ValueError('fat_header must be at least 62 bytes, got: %d' % len(fat_header))
  oem_id, code0, code1 = get_random_fat_salt()
  return ''.join((fat_header[:3], oem_id, fat_header[11 : 62], chr(code0), chr(code1)))


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


def parse_device_id(device_id):
  try:
    major, minor = map(int, device_id.split(':'))
  except ValueError:
    raise ValueError('Bad device_id syntax: %r' % device_id)
  if not (1 <= major <= 255 and 0 <= minor <= 255):
    raise ValueError('Bad device_id: %r' % device_id)
  return major, minor


def yield_dm_devices():
  setup_path_for_dmsetup()
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


def yield_dm_crypt_devices():
  setup_path_for_dmsetup()
  value = [run_and_read_stdout(('dmsetup', 'table'), is_dmsetup=True)]
  for line in value.pop().splitlines():
    # Example line: 'testvol: 0 2048 crypt aes-xts-plain64 0000000000000000000000000000000000000000000000000000000000000000 0 7:0 4096 1 allow_discards'.
    items = line.split(' ')
    if not items or not items[0].endswith(':'):
      continue
    name = items.pop(0)[:-1]
    if len(items) < 8 or items[0] != '0' or items[2] != 'crypt':
      continue
    yield (name, parse_device_id(items[6]))


def setup_path_for_dmsetup(do_add_usr=False):
  """Idempotent."""
  path = os.getenv('PATH', '/bin:/usr/bin')
  path_split = path.split(os.path.pathsep)
  if do_add_usr:
    if ('/usr/local/sbin' in path_split and
        '/usr/sbin' in path_split and
        '/sbin' in path_split):
      return
    extra = ':/usr/local/sbin:/usr/sbin:/sbin'
  else:
    if '/sbin' in path_split:
      return
    extra = ':/sbin'
  os.environ['PATH'] += extra.replace(':', os.path.pathsep)


def fsync_loop_device(f):
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


def parse_keytable_arg(arg, keytable_size, is_short_ok):
  if arg is None:
    return None
  value = arg[arg.find('=') + 1:].lower()
  if value in ('random', 'new', 'rnd'):
    value = get_random_bytes(keytable_size)
  else:
    try:
      value = value.decode('hex')
    except (TypeError, ValueError):
      raise UsageError('keytable value must be hex: %s' % arg)
  if is_short_ok:
    if len(value) not in (32, 48, 64):
      raise UsageError('keytable must be 32, 48 or 64 bytes: %s' % arg)
  else:
    if len(value) != 64:
      raise UsageError('keytable must be 64 bytes: %s' % arg)
  return value


def get_passphrase_str(passphrase):
  if callable(passphrase):
    passphrase = passphrase()  # Prompt the user.
  if passphrase is None:
    passphrase = prompt_passphrase(do_passphrase_twice=False)
  if not isinstance(passphrase, str):
    raise TypeError
  return passphrase


def find_dm_crypt_device(device):
  expected_device_id = None
  if device.startswith('/dev/mapper/'):
    name = device.split('/', 3)[3]
  else:
    stat_obj = os.stat(device)
    if stat.S_ISDIR(stat_obj.st_mode):  # A directory on a mounted filesystem on a dm-crypt encrypted device.
      major_minor = stat_obj.st_dev >> 8, stat_obj.st_dev & 255
    elif stat.S_ISBLK(stat_obj.st_mode):  # A dm-crypt e.
      major_minor = stat_obj.st_rdev >> 8, stat_obj.st_rdev & 255
    else:
      raise UsageError(
          'device must be a directory or a dm device, got: %r' %
          device)
    setup_path_for_dmsetup()
    for name2, major_minor2 in yield_dm_devices():  # major_minor2 is of /dev/mapper/... device.
      if major_minor == major_minor2:
        name = name2
        break
    else:
      for name2, major_minor2 in yield_dm_crypt_devices():  # major_minor2 is of raw device.
        if major_minor == major_minor2:
          name, expected_device_id = name2, major_minor2
          break
      else:
        raise ValueError('Not a dm device: %r' % device)
  check_table_name(name)
  return name, expected_device_id


def find_device_by_id(device_id):
  device_int = device_id[0] << 8 | device_id[1]
  for entry in sorted(os.listdir('/dev')):
    device2 = '/dev/' + entry
    try:
      stat_obj = os.stat(device2)
    except OSError, e:
      continue
    if stat.S_ISBLK(stat_obj.st_mode) and stat_obj.st_rdev == device_int:
      return device2
  else:
    raise RuntimeError('Raw device %s not found in /dev.' % device_id)


class DmCryptFlushingFile(object):
  """A file-like object with a decrypting region. Needs Linux dm-crypt.

  This object calls .read(...) and .write(...) on filename normally, except
  that the region file_data[decrypted_ofs : decrypted_ofs + decrypted_size])
  gets written through decrypted_file and decrypted with aes-xts-plain64.

  This class works around this Linux dm-crypt buffer (and probably page
  cache) flushing issue: some writes to the raw device don't show in the
  /dev/mapper/... device, especially if the latter has a filesystem mounted.
  As a workaround, this class emulates writing to the raw device by writing
  decrypted AES blocks to the /dev/mapper/... device, and also calling
  fsync and the ioctl BLKFLSBUF.
  """

  __slots__ = ('_do', '_ds', '_keytable', '_iv_ofs', '_f', '_df', '_fsync',
               '_ioctl', '_BLKFLSBUF', '_codebook1')

  def __init__(self, filename, decrypted_ofs, decrypted_size, decrypted_filename, keytable, iv_ofs):
    import fcntl
    # Make __del__ work.
    self._f = self._df = None
    self._fsync = os.fsync
    self._ioctl = fcntl.ioctl
    # Linux ioctl number for `blockdev --flushbufs', we need it in __del__.
    self._BLKFLSBUF = 0x1261
    # Is this call needed? Playing it safe and detecting the block device
    # early. This call fails unless self._f is a block device.

    check_decrypted_ofs(decrypted_ofs)
    check_decrypted_ofs(iv_ofs)
    check_decrypted_size(decrypted_size)
    check_aes_xts_key(keytable)
    self._do = decrypted_ofs
    self._ds = decrypted_size
    self._keytable = keytable
    self._iv_ofs = iv_ofs
    self._codebook1 = new_aes(keytable[:len(keytable) >> 1])

    self._f = open(filename, 'r+b')
    is_ok = False
    try:
      self._df = open(decrypted_filename, 'r+b')
      is_ok = True
    finally:
      if not is_ok:
        self._f.close()
    self._ioctl(self._f.fileno(), self._BLKFLSBUF)

  def close(self):
    # The fsync and BLKFLSBUF tricks seem to propagate the write output not
    # only to self._f, but also to the backing file of loop device self._f
    # as well.
    if self._df:  # Earlier or later?
      try:
        self._df.flush()  # Needed.
        self._fsync(self._df.fileno())
        self._df.close()
      finally:
        self._df = None
    if self._f:
      try:
        self._f.flush()
        self._fsync(self._f.fileno())  # Not needed, but playing it safe.
        self._ioctl(self._f.fileno(), self._BLKFLSBUF)
        self._f.close()
      finally:
        self._f = None

  def full_flush(self):
    self._df.flush()
    self._fsync(self._df.fileno())
    self._f.flush()
    self._fsync(self._f.fileno())
    self._ioctl(self._f.fileno(), self._BLKFLSBUF)

  def __del__(self):
    self.close()

  def fileno(self):
    return self._f.fileno()

  def flush(self):
    self._df.flush()
    self._f.flush()

  def tell(self):
    return self._f.tell()

  def truncate(self, size):
    raise IOError(0, '.truncate() not supported')

  def seek(self, *args):
    return self._f.seek(*args)

  def read(self, size):
    if ofs + size <= self._do or ofs >= self._do + self._ds:
      return self._f.read(size)
    # TODO(pts): Add support if needed, use _crypt_aes_xts_sectors.
    raise ValueError('Reading from the encrypted region not suported.')

  def write(self, data):
    data = buffer(data)
    ofs = self._f.tell()
    while data:
      if ofs + len(data) <= self._do or ofs >= self._do + self._ds:
        self._f.write(data)  # Shortcut.
        return
      size = min(len(data), 512 - (ofs & 511))
      if self._do <= ofs < self._do + self._ds:
        if ofs & 15:
          raise ValueError('Write offset must be divisible by 16, got: %d' % ofs)
        if size & 15:
          raise ValueError('Write size must be divisible by 16, got: %d' % size)
        if ofs + size > self._do + self._ds:
          raise ValueError('Write spans from decrypted to raw.')
        self._df.seek(ofs - self._do)
        self._df.write(crypt_aes_xts(self._keytable, data, do_encrypt=False, codebook1_crypt=self._codebook1.decrypt, sector_idx=(ofs - self._do + self._iv_ofs) >> 9, ofs=(ofs & 511)))
        self._f.seek(ofs + size)
      else:
        self._f.write(data)
      ofs += size
      data = buffer(data, size)


def find_on_path(progname):
  if os.path.sep in progname:
    return progname
  for dirname in os.getenv('PATH', '').split(os.path.pathsep):
    if dirname:
      pathname = os.path.join(dirname, progname)
      if os.path.isfile(pathname):
        return pathname
  return None


try:
  shell_escape = __import__('pipes').quote
  if not callable(shell_escape):
    raise TypeError
except (ImportError, AttributeError, TypeError):
  def shell_escape(string):
    """Escapes shell metacharacters on Unix."""
    if '\0' in string:
      raise ValueError('NUL not allowed in command-line argument.')
    # TODO(pts): Add -+,:/
    # We don't use `import re' to avoid the dependency.
    if string and (string.replace('_', '').replace('.', '').replace('/', '') or 'x').isalnum():
      return string
    return "'%s'" % string.replace("'", "'\\''")


# --- LUKS.


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
    raise ValueError('decrypted_ofs must be at least 4096 for LUKS, got: %d' % decrypted_ofs)
  if decrypted_ofs & 511:
    raise ValueError('decrypted_ofs must be a multiple of 512, got: %d' % decrypted_ofs)


def check_luks_key_material_ofs(key_material_ofs):
  if key_material_ofs < 1024:
    raise ValueError('key_material_ofs must be nonnegative, got: %d' % key_material_ofs)
  if key_material_ofs & 511:
    raise ValueError('key_material_ofs must be a multiple of 512, got: %d' % key_material_ofs)


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


def get_recommended_luks_decrypted_ofs(device_size):
  device_size = min(device_size, 512 << 20)
  result = 8 << 10  # Larger than LUKS cryptsetup minimum (4096), can store all 8 slots, good SSD page alignment.
  while device_size >= (result << 9):
    result <<= 1
  # At most 0.4% overhead if device_size >= 2 << 20, at most 2 MiB (default
  # LUKS header size, >1 MiB default partition alignment).
  return result


def get_recommended_luks_af_stripe_size(decrypted_ofs):
  if not isinstance(decrypted_ofs, (int, long)):
    raise TypeError
  if decrypted_ofs >= (2001 << 10):
    # Use at most 2000 KiB for slots. This corresponds to the cryptsetup
    # default of af_stripe_count == 4000, slot_count == 8, cipher ==
    # 'aes-xts-plain64'.
    af_stripe_size = (2000 << 10) >> (3 + 9) << 9
    assert 1 <= af_stripe_size <= 256000
    return af_stripe_size
  header_size = 1024  # Minimum LUKS PHDR size.
  while decrypted_ofs >= header_size * 10 and header_size < (32 << 10):
    header_size <<= 1
  # af_stripe_count <= 0 is an error, `slot_count <= 0' below will report it.
  return (decrypted_ofs - header_size) >> (3 + 9) << 9


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
    crypt_sectors_func, get_codebooks_func, af_salt=None):
  check_aes_xts_key(keytable)
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
  header_key = pbkdf2(  # Slow.
      passphrase, slot_salt, len(keytable), slot_iterations, digest_cons,
      digest_blocksize)
  header_codebooks = get_codebooks_func(header_key)
  key_material = crypt_sectors_func(header_codebooks, split_key, do_encrypt=True)
  assert len(key_material) == key_material_size
  key_slot_data = struct.pack(
      '>LL32sLL', active_tag, slot_iterations, slot_salt, key_material_ofs >> 9,
      stripe_count)
  assert len(key_slot_data) == 48
  return key_slot_data, key_material


def build_luks_inactive_key_slot(slot_iterations, key_material_ofs, af_stripe_count):
  check_luks_key_material_ofs(key_material_ofs)
  inactive_tag = 0xdead
  return struct.pack(
      '>LL32xLL', inactive_tag, slot_iterations, key_material_ofs >> 9,
      af_stripe_count)


def check_luks_uuid(uuid):
  # Any random 16 bytes will do, typically it looks like:
  # '40bf7c9f-12a6-403f-81da-c4bd2183b74a'.
  if '\0' in uuid:
    raise ValueError('NUL not allowed in LUKS uuid: %r' % uuid)
  if len(uuid) > 36:
    raise ValueError(
        'LUKS uuid must be at most 36 bytes: %r' % uuid)


def build_luks_header(
    passphrase, decrypted_ofs=None, keytable_salt=None,
    uuid=None, pim=None, keytable_iterations=None, slot_iterations=None,
    cipher='aes-xts-plain64', hash='sha512', keytable=None, slot_salt=None,
    af_stripe_count=None, af_salt=None, key_size=None):
  """Builds a LUKS1 header.

  Similar to `cryptsetup luksFormat', with the following differences:

  * Calculation of default af_stripe_count is a bit different.
  * For decrypted_ofs=4096 (smaller than the default), the header supports
    only 6 key slots
    (instead of the `cryptsetup luksFormat' default of 8).
    Specify decrypted_ofs=4608 for 7 key slots, or secrypted_ofs>=5120 for 8
    key slots.
  * Supports only --cipher=aes-xts-plain64 and --cipher=aes-cbc-essiv:sha256,
    --cipher=aes-cbc-plain, --cipher=aes-cbc-plain64.
    `cryptsetup luksFormat' default is --hash=sha1 --cipher=aes-xts-plain64.
  * Doesn't try to autodetect iteration count based on CPU speed.
  * Specify pim=-14 to make PBKDF2 faster, but only do it if you have a very
    strong, randomly generated password of at least 64 bytes of entropy.
  * It's more configurable (e.g. decrypted_ofs and af_stripe_count).
  * `cryptsetup luksAddKey' will fail if af_stripe_count < 4000 (sometimes
    default).

  Returns:
    String containing the LUKS1 partition header (phdr) and the key material.
    To open it, copy it to the beginning of a raw device, and use
    `sudo cryptsetup open ... --type=luks'.
  """
  # Based on https://gitlab.com/cryptsetup/cryptsetup/blob/master/docs/on-disk-format.pdf
  # version 1.2.3.
  if key_size & 7:  # Number of bits.
    raise ValueError('key_size must be a multiple of 8, got: %d' % key_size)
  keytable_size = key_size >> 3
  cipher = cipher.lower()
  crypt_sectors_func, get_codebooks_func = get_crypt_sectors_funcs(cipher, keytable_size)
  cipher_name, cipher_mode = cipher.split('-', 1)

  # If the caller has alignment requirements, then it should specify a large
  # enough decrypted_ofs (e.g. multiple of 1 MiB for good SSD block
  # alignment) based on device_size.
  if decrypted_ofs is None:  # Make it as small as possible with 8 key slots.
    if af_stripe_count is None:
      af_stripe_count = 512 // keytable_size  # Fit to 1 sector.
    # Make room for all 8 key slots.
    decrypted_ofs = (2 + 8) << 9
  check_luks_decrypted_ofs(decrypted_ofs)

  if af_stripe_count is None:
    af_stripe_count = get_recommended_luks_af_stripe_size(decrypted_ofs) // keytable_size
  key_material_sector_count = max(1, (af_stripe_count * keytable_size + 511) >> 9)
  # 6 slots for the default decrypted_ofs == 4096.
  slot_count = min(8, ((decrypted_ofs >> 9) - 2) // key_material_sector_count)
  if slot_count <= 0:
    raise ValueError('Not enough room for slots, increase decrypted_ofs to %d or decrease af_stripe_count to %d.' %
                     ((2 + key_material_sector_count) << 9, (decrypted_ofs - 1024) // keytable_size))

  if uuid is None:
    uuid = get_random_bytes(16).encode('hex')
    uuid = '-'.join((  # Add the dashes.
        uuid[:8], uuid[8 : 12], uuid[12 : 16], uuid[16 : 20], uuid[20:]))
  check_luks_uuid(uuid)
  slot_iterations_orig = slot_iterations
  if keytable_iterations is None:
    # `cryptsetup luksFormat' measures the CPU speed for this.
    total_iterations = get_iterations(pim, False, hash)
    # The ratio by `cryptsetup luksFormat' is ~8 : 1, we have 7 : 1.
    keytable_iterations = max(1000, total_iterations >> 3)
    if slot_iterations is None:
      slot_iterations = max(1000, total_iterations - keytable_iterations)
  elif pim:
    raise ValueError('Both pim= and keytable_iterations= are specified.')
  check_iterations(keytable_iterations)
  if slot_iterations is None:
    slot_iterations = max(1000, keytable_iterations << 3)
  elif pim and slot_iterations_orig is not None:
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
  if slot_count < 8:
    sys.stderr.write('warning: only %d of 8 slots are usable, increase decrypted_ofs to %d or decrease af_stripe_count to %d to get all\n' %
                     (slot_count, (2 + 8 * key_material_sector_count) << 9, ((decrypted_ofs - 1024) >> 12 << 9) // keytable_size))

  # Do this as late as possible, after `raise ValueError' checks above.
  if callable(passphrase):
    passphrase = passphrase()  # Prompt user for passphrase.
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

  signature = 'LUKS\xba\xbe'
  version = 1
  mk_digest = pbkdf2(  # Slow.
      keytable, keytable_salt, 20, keytable_iterations,
      digest_cons, digest_blocksize)
  output = [struct.pack(
      '>6sH32s32s32sLL20s32sL40s',
      signature, version, cipher_name, cipher_mode, hash, decrypted_ofs >> 9,
      keytable_size, mk_digest, keytable_salt, keytable_iterations, uuid)]
  key_materials = []
  # Put key material as late as possible, make padding after PHDR as long as
  # possible so that autodetection tools (/sbin/blkid) won't mistakenly
  # detect the LUKS volume as another filesystem. If the raw device is long
  # enough, total size of PHDR + padding will be 48 KiB.
  key_material_sector_base = (decrypted_ofs >> 9) - slot_count * key_material_sector_count
  assert key_material_sector_base >= 2
  for i in xrange(8):
    key_material_ofs = (key_material_sector_base + min(i, slot_count - 1) * key_material_sector_count) << 9
    if i < len(passphrases):
      # Let build_luks_active_key_slot generate random slot_salt values if
      # needed.
      key_slot_data, key_material = build_luks_active_key_slot(
          slot_iterations, slot_salt, keytable, passphrases[i],
          digest_cons, digest_blocksize, key_material_ofs, af_stripe_count,
          crypt_sectors_func, get_codebooks_func, af_salt)
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
          slot_iterations, key_material_ofs, af_stripe_count))
      if i < slot_count:
        key_materials.append('\0' * (key_material_sector_count << 9))
  output.append('\0' * 432)  # Align PHDR to sector boundary.
  # Padding between PHDR and key_material_sector_base.
  output.append('\0' * ((key_material_sector_base - 2) << 9))
  output.extend(key_materials)
  output_size = sum(map(len, output))
  padded_output_size = min(decrypted_ofs, 65536 + 1024)
  # Destroy any previous filesystem headers.
  output.append('\0' * (padded_output_size - output_size))
  result = ''.join(output)
  assert not len(result) & 511
  assert len(result) <= decrypted_ofs
  return result


def get_open_luks_info(f, passphrase):
  """Opens key slots with passphrase, returns keytable and other info.

  This function works with multiple ciphers (--cipher=aes-xts-plain64 and
  --cipher=aes-cbc-essiv:sha256), multiple hashes such as --hash=sha512, and
  any key size such as --key-size=512.

  Returns:
    (decrypted_ofs, keytable).
  """
  f.seek(0)
  header = f.read(592)
  if len(header) < 592:
    raise ValueError('Too short for LUKS1.')
  if not header.startswith('LUKS\xba\xbe\0\1'):
    raise ValueError('LUKS1 signature not found.')
  (signature, version, cipher_name, cipher_mode, hash, decrypted_sector_idx,
   keytable_size, mk_digest, keytable_salt, keytable_iterations, uuid,
  ) = struct.unpack('>6sH32s32s32sLL20s32sL40s', buffer(header, 0, 208))
  decrypted_ofs = decrypted_sector_idx << 9
  cipher_name = cipher_name.rstrip('\0')
  cipher_mode = cipher_mode.rstrip('\0')
  hash = hash.rstrip('\0')
  uuid = uuid.rstrip('\0')  # ASCII-formatted, hex with dashes.
  if cipher_name.lower() != 'aes':
    raise ValueError('Unsupported cipher: %r' % cipher_name)
  cipher = '-'.join((cipher_name, cipher_mode)).lower()
  crypt_sectors_func, get_codebooks_func = get_crypt_sectors_funcs(cipher, keytable_size)
  digest_cons, digest_blocksize = get_hash_digest_params(hash)
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
      # Such a modulo would make decrypting with crypt_aes_xts_sectors raise a
      # ValueError, because crypt_aes_xts is not defined for such sizes.
      # However, it never happens here, because keytable_size is a multiple of 32.
      assert not 0 < (slot_key_material_size & 511) < 16
      minimum_decrypted_sector_idx = slot_key_material_sector_idx + ((slot_key_material_size + 511) >> 9)
      if decrypted_sector_idx < minimum_decrypted_sector_idx:  # `cryptsetup open' also checks this.
        raise ValueError('decrypted_sector_idx must be at least %d because of an active slot, got: %d' %
                         (minimum_decrypted_sector_idx, decrypted_sector_idx))
      active_slots.append((slot_idx, slot_iterations, slot_key_material_sector_idx, slot_stripe_count, slot_salt))
    elif slot_active_tag != 0xdead:
      raise ValueError('Unknown slot_active_tag: 0x%x' % slot_active_tag)
  if not active_slots:
    raise ValueError('No active LUKS slots found, it\'s impossible to open the volume even with a correct password.')
  print >>sys.stderr, 'info: found %d active LUKS slot%s' % (len(active_slots), 's' * (len(active_slots) != 1))
  passphrase = get_passphrase_str(passphrase)  # Prompt the user late.
  for slot_idx, slot_iterations, slot_key_material_sector_idx, slot_stripe_count, slot_salt in active_slots:
    f.seek(slot_key_material_sector_idx << 9)
    slot_key_material_size = slot_stripe_count * keytable_size
    slot_key_material = f.read(slot_key_material_size)
    if len(slot_key_material) < slot_key_material_size:
      raise ValueError('EOF in slot %d key material on raw device.' % slot_idx)
    slot_header_key = pbkdf2(  # Slow.
        passphrase, slot_salt, keytable_size, slot_iterations, digest_cons,
        digest_blocksize)
    slot_header_codebooks = get_codebooks_func(slot_header_key)
    slot_split_key = crypt_sectors_func(slot_header_codebooks, slot_key_material, do_encrypt=False)
    slot_keytable = luks_af_join(slot_split_key, slot_stripe_count, digest_cons)
    slot_mk_digest = pbkdf2(  # Slow.
        slot_keytable, keytable_salt, 20, keytable_iterations,
        digest_cons, digest_blocksize)
    if slot_mk_digest == mk_digest:
      print >>sys.stderr, 'info: passphrase correct for slot %d' % slot_idx
      break
    if len(active_slots) != 1:
      print >>sys.stderr, 'info: passphrase incorrect for slot %d' % slot_idx
  else:
    raise IncorrectPassphraseError('Incorrect passphrase for LUKS volume.')
  f.seek(decrypted_ofs)
  if len(f.read(512)) != 512:
    raise ValueError('decrypted_ofs beyond end of raw device.')
  return decrypted_ofs, slot_keytable, cipher


def is_luks1(enchd):
  if not enchd.startswith('LUKS\xba\xbe\0\1') or len(enchd) < 208:
    return False
  if enchd[8 : 9] == '\0':  # --fake-luks-uuid=...
    return False
  (signature, version, cipher_name, cipher_mode, hash, decrypted_sector_idx,
   keytable_size, mk_digest, keytable_salt, keytable_iterations, uuid,
  ) = struct.unpack('>6sH32s32s32sLL20s32sL40s', buffer(enchd, 0, 208))
  decrypted_ofs = decrypted_sector_idx << 9
  cipher_name = cipher_name.rstrip('\0')
  cipher_mode = cipher_mode.rstrip('\0')
  hash = hash.rstrip('\0')
  uuid = uuid.rstrip('\0')
  if not (2 <= len(cipher_name) <= 10 and 2 <= len(cipher_mode) <= 20 and 3 <= len(hash) <= 10 and len(uuid) <= 36):
    return False
  if not ''.join((cipher_name, cipher_mode, hash)).replace('-', '').replace(':', '').isalnum():
    return False
  # It looks like enchd is a LUKS1 encrypted volume header.
  return True


# ---


class UsageError(SystemExit):
  """Raised when there is a problem in the command-line."""


TEST_PASSPHRASE = 'ThisIsMyVeryLongPassphraseForMyVeraCryptVolume'
TEST_SALT = "~\xe2\xb7\xa1M\xf2\xf6b,o\\%\x08\x12\xc6'\xa1\x8e\xe9Xh\xf2\xdd\xce&\x9dd\xc3\xf3\xacx^\x88.\xe8\x1a6\xd1\xceg\xebA\xbc]A\x971\x101\x163\xac(\xafs\xcbF\x19F\x15\xcdG\xc6\xb3"


def update_truecrypt_mode(truecrypt_mode, type_value):
  if type_value == 'tcrypt':
    if truecrypt_mode == 0:  # Keep --veracrypt.
      return 0
    # --truecrypt. To open VeraCrypt, use `--type=tcrypt --veracrypt'.
    return 2
  elif type_value == 'truecrypt':
    return 2
  elif type_value == 'veracrypt':
    return 0
  elif type_value in ('luks', 'luks1'):
    return 3
  else:
    # Cryptsetup also supports --type=plain and --type=loopaes.
    raise UsageError('unsupported flag value: --type=%s' % type_value)


def cmd_get_table(args):
  # Please note that the commands cmd_get_table and cmd_get_mount are not
  # able to open all VeraCrypt, TrueCrypt and LUKS volumes: they work only
  # with some hashes (e.g. --hash=sha512) and one cipher
  # (--cipher=aes-xts-plain64), which matches the default for VeraCrypt
  # 1.17, TrueCrypt and cryptsetup-1.7.3. Also hidden and system volumes
  # are not supported. See the README.txt for more limitations.

  truecrypt_mode = None
  pim = device = passphrase = hash = display_device = None
  do_showkeys = False

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
    elif (arg in ('--type', '-M') and i < len(args)) or arg.startswith('--type='):  # cryptsetup.
      if '=' in arg:
        type_value = arg[arg.find('=') + 1:].lower()
      else:
        type_value = args[i]
        i += 1
      truecrypt_mode = update_truecrypt_mode(truecrypt_mode, type_value)
    elif arg.startswith('--password='):
      # Unsafe, ps(1) can read it.
      passphrase = parse_passphrase(arg)
    elif arg in ('--test-passphrase', '--test-password'):
      # With --test-passphase --salt=test it's faster, because
      # build_header_key is much faster.
      passphrase = TEST_PASSPHRASE
    elif arg.startswith('--hash='):
      hash = parse_veracrypt_hash_arg(arg)
    elif arg.startswith('--display-device='):
      display_device = arg[arg.find('=') + 1:]
    elif arg == '--showkeys':  # Similar to `dmsetup table --showkeys'.
      do_showkeys = True
    elif arg == '--no-showkeys':
      do_showkeys = False
    else:
      raise UsageError('unknown flag: %s' % arg)
  del value  # Save memory.
  if truecrypt_mode is None:
    truecrypt_mode = 1
  if device is None:
    if i >= len(args):
      raise UsageError('missing <device> hosting the encrypted volume')
    device = args[i]
    i += 1
  if i != len(args):
    raise UsageError('too many command-line arguments')

  #device_id = '7:0'
  device_id = device  # TODO(pts): Option to display major:minor.
  sys.stdout.write(get_table(device, passphrase, device_id, pim=pim, truecrypt_mode=truecrypt_mode, hash=hash, do_showkeys=do_showkeys, display_device=display_device))
  sys.stdout.flush()


def parse_veracrypt_hash_arg(arg):
  value = arg[arg.find('=') + 1:].lower().replace('-', '')
  allowed_values = set(item[3] for item in SETUP_MODES)
  if value not in allowed_values:
    raise UsageError('hash not allowed in TrueCrypt/VeraCrypt volumes, choose any of %r: %s' %
                     (tuple(allowed_values), arg))
  if not is_hash_supported(value):
    # tinyveracrypt doesn't know how to compute this hash.
    raise UsageError('unsupported hash: %s' % arg)
  return value


def cmd_mount(args):
  # This function is Linux-only.
  import subprocess

  is_custom_name = False
  pim = keyfiles = filesystem = hash = encryption = slot = device = passphrase = truecrypt_mode = protect_hidden = type_value = name = None

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
      value = arg[arg.find('=') + 1:]
      if value != '':
        raise UsageError('unsupported flag value: %s' % arg)
      keyfiles = value
    elif arg.startswith('--protect-hidden='):
      protect_hidden = arg[arg.find('=') + 1:].lower()
    elif arg == '--custom-name':
      is_custom_name = True
    elif arg == '--no-custom-name':
      is_custom_name = False
    elif (arg in ('--type', '-M') and i < len(args)) or arg.startswith('--type='):  # cryptsetup.
      if '=' in arg:
        type_value = arg[arg.find('=') + 1:].lower()
      else:
        type_value = args[i]
        i += 1
      if type_value == 'luks1':
        type_value = 'luks'
      if type_value in ('plain', 'loopaes', 'luks2'):
        raise UsageError('unsupported type, run this instead: cryptsetup open --type=%s ...' % type_value)
      truecrypt_mode = update_truecrypt_mode(truecrypt_mode, type_value)
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
    elif arg.startswith('--cipher='):  # Ignored for LUKS.
      value = arg[arg.find('=') + 1:].lower()
      if value != 'aes-xts-plain64':
        raise UsageError('unsupported flag value: %s' % arg)
      encryption = 'aes'
    elif arg.startswith('--hash='):
      hash = parse_veracrypt_hash_arg(arg)
    elif arg.startswith('--filesystem='):
      value = arg[arg.find('=') + 1:].lower().replace('-', '')
      if value != 'none':
        raise UsageError('unsupported flag value: %s' % arg)
      filesystem = value
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
  if filesystem != 'none':
    raise UsageError('missing flag: --filesystem=none')
  if protect_hidden != 'no':
    raise UsageError('missing flag: --protect-hidden=no')
  if keyfiles != '':
    raise UsageError('missing flag: --keyfiles=')
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
    print >>sys.stderr, 'info: using dmsetup table <name>: %s' % name

  if not had_dmsetup:
    # yield_dm_devices() also reports a permission error (and recommends
    # sudo) if run as non-root. Good.
    if name in (item[0] for item in yield_dm_devices()):
      raise SystemExit('dmsetup table <name> already in use: %s' % name)

  def block_device_callback(block_device, fd, device_id):
    table = get_table(device, passphrase, device_id, pim=pim, truecrypt_mode=truecrypt_mode, hash=hash, do_showkeys=True)  # Slow.
    run_and_write_stdin(('dmsetup', 'create', name), table, is_dmsetup=True)

  ensure_block_device(device, block_device_callback)


def cmd_close(args):
  # This function is Linux-only.

  if not args:
    raise UsageError('missing dmsetup table <name> for the encrypted volume')
  setup_path_for_dmsetup()
  # TODO(pts): Run ioctl(2) manually instead of dmsetup(8).
  #            Do we need to notify udev?
  #            Which dm-crypt version should we use (4, 3, 2 or 1)?
  #            Where does the event_nr below come from?
  #            Why are the sem...(...) calls done?
  #            Why is /run/udev/control access(2)ed?
  #            Do we need to call udev manually to update /dev/disk/... ? (/run/udev/queue.bin)
  #            Do we need to create the block device nodes in /dev/mapper/ (either we or udev; cryptsetup doesn't create it)?
  #
  # --noudevsync
  # Command not supported. Recompile with "--enable-udev-sync" to enable.
  # Cookie value is not set while trying to call DM_DEVICE_RESUME, DM_DEVICE_REMOVE or DM_DEVICE_RENAME ioctl. Please, consider using libdevmapper's udev synchronisation interface or disable it explicitly by calling dm_udev_set_sync_support(0)
  # grep  ' device-mapper' /proc/devices (misc?)
  #
  # stat("/dev/mapper/control", {st_mode=S_IFCHR|0600, st_rdev=makedev(10, 236), ...}) = 0
  # open("/dev/mapper/control", O_RDWR)     = 3
  # ioctl(3, DM_VERSION, 0x21d10f0)         = 0
  #
  # ioctl(5, DM_DEV_CREATE, {version=4.0.0, data_size=16384, name="testvol", uuid="CRYPT-LUKS1-40bf7c9f12a6403f81dac4bd2183b74a-testvol", flags=DM_EXISTS_FLAG} => {version=4.35.0, data_size=305, dev=makedev(254, 2), name="testvol", uuid="CRYPT-LUKS1-40bf7c9f12a6403f81dac4bd2183b74a-testvol", target_count=0, open_count=0, event_nr=0, flags=DM_EXISTS_FLAG}) = 0
  # ioctl(5, DM_TABLE_LOAD, {version=4.0.0, data_size=16384, data_start=312, name="testvol", target_count=1, flags=DM_EXISTS_FLAG|DM_SECURE_DATA_FLAG, {sector_start=0, length=4028, target_type="crypt", string="aes-xts-plain64 030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132 0 /dev/loop0 8"}} => {version=4.35.0, data_size=305, data_start=312, dev=makedev(254, 2), name="testvol", uuid="CRYPT-LUKS1-40bf7c9f12a6403f81dac4bd2183b74a-testvol", target_count=0, open_count=0, event_nr=0, flags=DM_EXISTS_FLAG|DM_INACTIVE_PRESENT_FLAG}) = 0
  # ioctl(5, DM_DEV_SUSPEND, {version=4.0.0, data_size=16384, name="testvol", event_nr=4210181, flags=DM_EXISTS_FLAG|DM_SECURE_DATA_FLAG} => {version=4.35.0, data_size=305, dev=makedev(254, 2), name="testvol", uuid="CRYPT-LUKS1-40bf7c9f12a6403f81dac4bd2183b74a-testvol", target_count=1, open_count=0, event_nr=0, flags=DM_EXISTS_FLAG|DM_ACTIVE_PRESENT_FLAG|DM_UEVENT_GENERATED_FLAG}) = 0
  #
  # ioctl(3, DM_DEV_REMOVE, {version=4.0.0, data_size=16384, name="testvol", event_nr=6312172, flags=DM_EXISTS_FLAG} => {version=4.35.0, data_size=305, name="testvol", uuid="CRYPT-LUKS1-40bf7c9f12a6403f81dac4bd2183b74a-testvol", flags=DM_EXISTS_FLAG|DM_UEVENT_GENERATED_FLAG}) = 0

  # --- dmsetup table:
  # ioctl(3, DM_VERSION, 0x13110f0)         = 0
  # ioctl(3, DM_TABLE_STATUS, 0x1311020)    = 0
  #
  # access("/run/udev/control", F_OK) = 0  # This is a socket.
  # semctl(0, 0, SEM_INFO, 0x7ffe330c3f50) = 0
  # semget(0xd4d3e05, 1, IPC_CREAT|IPC_EXCL|0600) = 3473408
  # semctl(3473408, 0, SETVAL, 0x1)   = 0
  # semctl(3473408, 0, GETVAL, 0x7f7f1b4183aa) = 1
  # semop(3473408, [{0, 1, 0}], 1)    = 0
  # semctl(3473408, 0, GETVAL, 0x7f7f1b418347) = 2
  # semget(0xd4d3e05, 1, 000)         = 3473408
  # semctl(3473408, 0, GETVAL, 0x7f7f1b418377) = 2
  # semop(3473408, [{0, -1, IPC_NOWAIT}], 1) = 0
  # semop(3473408, [{0, 0, 0}], 1)    = 0
  # semctl(3473408, 0, IPC_RMID, 0)   = 0
  #
  # TODO(pts): Kill the corresponding truecrypt or veracrypt process. In /proc/mounts:
  #            truecrypt /tmp/.truecrypt_aux_mnt1 fuse.truecrypt rw,nosuid,nodev,relatime,user_id=0,group_id=0,allow_other 0 0
  #            Why does it emulate /tmp/.truecrypt_aux_mnt1/volume (which is the plaintext, decrypted device as a file)?
  #            There is also /tmp/.truecrypt_aux_mnt1/control . Should we use this to kill?
  run_and_write_stdin(('dmsetup', 'remove') + tuple(args), '', is_dmsetup=True)
  # TODO(pts): If the encrypted volume was created on /dev/loop/... without
  # autoclear, then run `losetup -d'.


def cmd_open_table(args):
  # This function is Linux-only.
  import subprocess

  device_size = 'auto'
  keytable = device = name = decrypted_ofs = end_ofs = iv_ofs = None
  cipher = 'aes-xts-plain64'

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
      decrypted_ofs = parse_decrypted_ofs_arg(arg)
    elif arg.startswith('--end-ofs='):
      end_ofs = parse_decrypted_ofs_arg(arg)
    elif arg.startswith('--iv-ofs='):  # --iv-ofs=0 for LUKS, unspecified for VeraCrypt.
      iv_ofs = parse_decrypted_ofs_arg(arg)
    elif arg.startswith('--keytable='):
      # TODO(pts): Add --key-size=...
      keytable = parse_keytable_arg(arg, keytable_size=64, is_short_ok=True)
    elif arg.startswith('--cipher='):
      cipher = arg[arg.find('=') + 1:].lower()
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
    raise UsageError('missing flag: --ofs=...; try --ofs=8192')
  if end_ofs is None:
    raise UsageError('missing flag: --end-ofs=...; try --end-ofs=0')

  if device_size == 'auto':
    f = open(device, 'rb')
    try:
      f.seek(0, 2)
      device_size = f.tell()
    finally:
      f.close()
  if device_size < decrypted_ofs + end_ofs:
    raise UsageError('raw device too small for dmsetup table, size: %d' % device_size)
  decrypted_size = device_size - decrypted_ofs - end_ofs
  if iv_ofs is None:
    iv_ofs = decrypted_ofs

  def block_device_callback(block_device, fd, device_id):
    table = build_table(keytable, decrypted_size, decrypted_ofs, device_id, iv_ofs, cipher, True)
    run_and_write_stdin(('dmsetup', 'create', name), table, is_dmsetup=True)

  ensure_block_device(device, block_device_callback)


def parse_luks_uuid_flag(uuid_flag, is_any_luks_uuid):
  if is_any_luks_uuid:
    # Any bytes can be used (not only hex), blkid recognizes them as UUID.
    if '\0' in uuid_flag:
      raise UsageError('NUL not allowed in LUKS uuid: %r' % uuid_flag)
    if len(uuid_flag) > 36:
      raise UsageError(
          'LUKS uuid must be at most 36 bytes: %r' % uuid_flag)
    return uuid_flag
  if uuid_flag in ('random', 'new', 'rnd'):
    uuid = ''
  else:
    uuid = uuid_flag.replace('-', '').lower()
    try:
      uuid = uuid.decode('hex')
    except (TypeError, ValueError):
      raise UsageError('LUKS uuid must be hex: %r' % uuid_flag)
  if not uuid:
    uuid = get_random_bytes(16)
  if len(uuid) != 16:
    raise UsageError(
        'uuid must be 16 bytes, got: %d' % len(uuid))
  uuid = uuid.encode('hex')
  return '-'.join((  # Add the dashes.
      uuid[:8], uuid[8 : 12], uuid[12 : 16], uuid[16 : 20], uuid[20:]))


def cmd_create(args):
  is_quick = False
  do_passphrase_twice = True
  salt = ''
  is_any_luks_uuid = False
  type_value = 'veracrypt'
  is_opened = False
  is_batch_mode = False
  do_restrict_luksformat_defaults = False
  is_luks_allowed = is_nonluks_allowed = True
  do_truncate = True
  keytable_arg = fake_luks_uuid_flag = decrypted_ofs = fatfs_size = do_add_full_header = do_add_backup = volume_type = device = device_size = hash = filesystem = pim = keyfiles = random_source = passphrase = None
  cipher = af_stripe_count = uuid_flag = uuid = None
  fat_label = fat_uuid = fat_rootdir_entry_count = fat_fat_count = fat_fstype = fat_cluster_size = None
  key_size = None
  do_skip_dash_dash = False

  i, value = 0, None
  while i < len(args):
    arg = args[i]
    if arg == '-' or not arg.startswith('-'):
      break
    i += 1
    if arg == '--':
      if do_skip_dash_dash:
        do_skip_dash_dash = False
      else:
        break
    elif arg.startswith('--password='):
      passphrase = parse_passphrase(arg)
    elif arg in ('--test-passphrase', '--test-password'):
      # With --test-passphase --salt=test it's faster, because
      # build_header_key is much faster.
      passphrase = TEST_PASSPHRASE
    elif arg.startswith('--keytable='):
      keytable_arg = arg
    elif arg.startswith('--salt='):
      value = arg[arg.find('=') + 1:]
      if value == 'test':
        salt = TEST_SALT
      elif value in ('random', 'new', 'rnd'):
        salt = ''
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
    elif arg.startswith('--fake-luks-uuid='):
      fake_luks_uuid_flag = arg[arg.find('=') + 1:]
    elif arg == '--any-luks-uuid':
      # If you specify a UUID in the wrong format,
      # `cryptsetup open' in cryptsetup-1.7.3 will fail with:
      # `Requested UUID Hello, has invalid format.'.
      is_any_luks_uuid = True
    elif arg == '--no-any-luks-uuid':
      is_any_luks_uuid = False
    elif arg.startswith('--uuid='):
      uuid_flag = arg[arg.find('=') + 1:]
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
        raise UsageError('FAT cluster size must be a power of 2: 512 ... 65536, got: %s' % arg)
    elif arg.startswith('--fat-count='):
      value = arg[arg.find('=') + 1:]
      try:
        fat_fat_count = int(value)
      except ValueError:
        raise UsageError('unsupported flag value: %s' % arg)
      if fat_fat_count not in (1, 2):
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
      cipher = 'aes-xts-plain64'
    elif arg.startswith('--cipher='):
      cipher = arg[arg.find('=') + 1:].lower()
    elif arg.startswith('--key-size='):
      value = arg[arg.find('=') + 1:]
      try:
        key_size = int(value)
      except ValueError:
        raise UsageError('unsupported flag value: %s' % arg)
    elif arg.startswith('--af-stripes='):  # LUKS anti-forensic stripe count.
      value = arg[arg.find('=') + 1:]
      try:
        af_stripe_count = int(value)
      except ValueError:
        raise UsageError('unsupported flag value: %s' % arg)
      if af_stripe_count <= 0:
        raise UsageError('af stripe count must be positive, got: %s' % arg)
    elif arg.startswith('--hash='):
      hash = parse_veracrypt_hash_arg(arg)
    elif arg.startswith('--filesystem='):
      filesystem = arg[arg.find('=') + 1:]
      if filesystem.lower().replace('-', '') == 'none':
        filesystem = 'none'
      if filesystem == 'fat1':
        do_skip_dash_dash = True
    elif arg.startswith('--keyfiles='):
      value = arg[arg.find('=') + 1:]
      if value != '':
        raise UsageError('unsupported flag value: %s' % arg)
      keyfiles = value
    elif arg.startswith('--random-source='):
      value = arg[arg.find('=') + 1:]
      if value != '/dev/urandom':
        raise UsageError('unsupported flag value: %s' % arg)
      random_source = value
    elif arg == '--use-urandom':  # `cryptsetup luksFormat'.
      random_source = '/dev/urandom'
    elif arg == '--use-random':  # `cryptsetup luksFormat'.
      # TODO(pts): Support this is --random-source=/dev/random .
      raise UsageError('unsupported flag value: %s' % arg)
    elif arg == '--batch-mode':  # `cryptsetup luksFormat'.
      is_batch_mode = True
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
    elif arg == '--truncate':
      do_truncate = True
    elif arg == '--no-truncate':
      do_truncate = False
    elif arg == '--passphrase-twice':
      do_passphrase_twice = True
    elif arg == '--verify-passphrase':  # cryptsetup create.
      do_passphrase_twice = True
    elif arg == '--passphrase-once':
      do_passphrase_twice = False
    elif arg == '--truecrypt':
      type_value = 'truecrypt'
    elif arg in ('--no-truecrypt', '--veracrypt'):
      type_value = 'veracrypt'
    elif (arg in ('--type', '-M') and i < len(args)) or arg.startswith('--type='):  # cryptsetup create.
      if '=' in arg:
        type_value = arg[arg.find('=') + 1:].lower()
      else:
        type_value = args[i]
        i += 1
      if type_value in ('tcrypt', 'truecrypt'):  # cryptsetup create --type=tcrypt.
        type_value = 'truecrypt'
      elif type_value == 'veracrypt':
        type_value = 'veracrypt'
      elif type_value in ('luks', 'luks1'):  # cryptsetup create --type=luks.
        type_value = 'luks'
      else:
        # Cryptsetup also supports --type=plain and --type=loopaes.
        raise UsageError('unsupported flag value: %s' % arg)
    elif arg.startswith('--restrict-type='):
      value = arg[arg.find('=') + 1:].lower()
      if value == 'no-luks':
        is_luks_allowed = False
      elif value == 'luks':
        is_nonluks_allowed = False
      else:
        raise UsageError('unsupported flag value: %s' % arg)
    elif arg == '--restrict-luksformat-defaults':
      do_restrict_luksformat_defaults = True
    else:
      raise UsageError('unknown flag: %s' % arg)
  del value  # Save memory.

  if filesystem == 'none':
    if (i < len(args) and
        (args[i].startswith('mkfs.') or '/mkfs.' in args[i])):
      filesystem = 'mkfs'  # Placeholder, change from 'none'.
      mkfs_args = list(args[i:])
      if device is None:
        if i + 1 == len(args):
          raise UsageError(
              'missing raw <device> hosting the encrypted volume, after mkfs')
        device = mkfs_args.pop()
    elif device is None:
      if i >= len(args):
        raise UsageError('missing raw <device> hosting the encrypted volume')
      device = args[i]
      i += 1
      mkfs_args = []
      if i != len(args):
        raise UsageError('too many command-line arguments')
  elif filesystem is None:
    raise UsageError('missing flag: --filesystem=...')
  else:
    mkfs_args = list(args[i:])
    mkfs_args[:0] = ('mkfs.' + filesystem,)
    if device is None:
      if i >= len(args):
        raise UsageError('missing raw <device> hosting the encrypted volume')
      device = mkfs_args.pop()
  if fatfs_size is not None:
    if decrypted_ofs is not None:
      raise UsageError('--mkfat=... conflicts with --ofs=...')
    decrypted_ofs = 'mkfat'
  if filesystem == 'fat1':
    if mkfs_args != ['mkfs.fat1']:
      # This happens only after double --.
      raise UsageError('too many arguments after --filesystem=fat1')
    if decrypted_ofs == 'fat':
      # TODO(pts): Make it work for decrypted_ofs != 0.
      raise UsageError('--filesystem=fat1 conflicts with --ofs=fat')
    if decrypted_ofs == 'mkfat':
      # TODO(pts): Make it work for decrypted_ofs != 0, with separate flags.
      raise UsageError('--filesystem=fat1 conflicts with --mkfat=...')
    if fake_luks_uuid_flag is not None and decrypted_ofs == 0:
      raise UsageError('--filesystem=fat1 conflicts with --fake-luks-uuid=... --ofs=0')
    del mkfs_args[:]
  # Now mkfs_args is a non-empty list iff we need mkfs. mkfs_args starts with
  # the command to run (e.g. 'mkfs.ext2'), and in the end it doesn't contain
  # the device filename or the filesystem size.

  if key_size is None and not is_opened:
    key_size = 256 << (cipher == 'aes-xts-plain64')
  if volume_type != 'normal':
    raise UsageError('missing flag: --volume-type=normal')
  if cipher is None:
    raise UsageError('missing flag: --encryption=aes')
  if keyfiles != '':
    raise UsageError('missing flag: --keyfiles=')
  if random_source != '/dev/urandom':
    if do_restrict_luksformat_defaults:
      raise UsageError('missing flag: --use-urandom')
    else:
      raise UsageError('missing flag: --random-source=/dev/urandom')
  if not is_batch_mode and do_restrict_luksformat_defaults:
      raise UsageError('missing flag: --batch-mode')
  if hash is None:
    raise UsageError('missing flag: --hash=...')
  if device_size is None:
    raise UsageError('missing flag: --size=..., recommended but not compatible with veracrypt create: --size=auto')
  if pim is None:  # For compatibility with `veracrypt --create'.
    if type_value == 'truecrypt':
      pim = 0
    else:
      raise UsageError('missing flag --pim=..., recommended: --pim=0')
  if fatfs_size is None and filesystem != 'fat1':
    if fat_label is not None:
      raise UsageError('--fat-label needs --mkfat=...')
    if fat_uuid is not None:
      raise UsageError('--fat-uuid needs --mkfat=...')
    if fat_rootdir_entry_count is not None:
      raise UsageError('--fat-rootdir-entry-count needs --mkfat=...')
    if fat_fat_count is not None:
      raise UsageError('--fat-count needs --mkfat=...')
    if fat_fstype is not None:
      raise UsageError('--fat-fstype needs --mkfat=...')
    if fat_cluster_size is not None:
      raise UsageError('--fat-cluster-size needs --mkfat=...')
  # This also generates random bytes if needed.
  keytable = parse_keytable_arg(keytable_arg, keytable_size=(key_size or 512) >> 3, is_short_ok=(type_value == 'luks'))

  if type_value == 'luks':
    if not is_luks_allowed:
      raise UsageError('--type=luks not allowed for this command, try init')
    if key_size and key_size & 3:
      raise UsageError('--key-size=... must be divisible by 8, got --key-size=%d' % key_size)
    try:
      get_crypt_sectors_funcs(cipher, key_size and key_size >> 3)  # key_size can be None here, good.
    except ValueError, e:
      e = str(e)
      raise UsageError(e[:1].lower() + e[1:].rstrip('.'))
    if decrypted_ofs is not None:
      if not isinstance(decrypted_ofs, (int, long)):
        raise UsageError('--type=luks conflicts with --ofs=%s' % decrypted_ofs)
      if decrypted_ofs < 4096:
        raise UsageError('--ofs=%d too small for --type=luks, minimum is 4096' % decrypted_ofs)
    if do_add_backup:
      raise UsageError('--type=luks conflicts with --add-backup')
    if do_add_full_header is False:
      raise UsageError('--type=luks conflicts with --no-add-full-header')
    if salt:  # TODO(pts): --salt=... and --slot-salt=... with proper lengths.
      raise UsageError('--type=luks conflicts with --salt=...')
    if decrypted_ofs == 'fat':
      raise UsageError('--type=luks conflicts with --ofs=fat')
    if decrypted_ofs == 'mkfat':
      raise UsageError('--type=luks conflicts with --mkfat=...')
    if fake_luks_uuid_flag is not None:
      raise UsageError('--type=luks conflicts with --fake-luks-uuid=..., use --uuid=... instead')
    if uuid_flag is not None:
      uuid = parse_luks_uuid_flag(uuid_flag, is_any_luks_uuid)
    do_add_full_header = True
    do_add_backup = False
  else:
    if not is_nonluks_allowed:
      raise UsageError('--type=%s not allowed for this command, try init' % type_value)
    if cipher != 'aes-xts-plain64':
      # --ofs=mkfat, --filesystem=fat1 doesn't work with any other cipher.
      raise UsageError('--type=%s needs --cipher=aes-xts-plain64, got --cipher=%s' % (type_value, cipher))
    if key_size not in (512, None):
      raise UsageError('--type=%s needs --key-size=512, got --key-size=%d' % (type_value, key_size))
    if af_stripe_count not in (1, None):
      raise UsageError('--type=%s conflicts with --af-stripe-count=...' % type_value)
    if fake_luks_uuid_flag is not None:
      if decrypted_ofs == 'fat':
        raise UsageError('--fake-luks-uuid=... conflicts with --ofs=fat')
      if decrypted_ofs == 'mkfat':
        raise UsageError('--fake-luks-uuid=... conflicts with --mkfat=...')
      uuid = parse_luks_uuid_flag(fake_luks_uuid_flag, is_any_luks_uuid)
    if uuid_flag is not None:
      raise UsageError('--type=%s conflicts with --uuid=..., maybe use --fake-looks-uuid=... instead' % type_value)
    if decrypted_ofs == 0 and type_value == 'truecrypt':
      raise UsageError('--ofs=0 too small for --type=truecrypt, minimum is 512')
  if mkfs_args:
    setup_path_for_dmsetup(do_add_usr=True)
    # This also fails if not run as root. Good.
    list(yield_dm_devices())
  if mkfs_args and '/' not in mkfs_args[0]:
    pathname = find_on_path(mkfs_args[0])
    if pathname is None:
      raise UsageError('mkfs program not found on PATH: %s' % mkfs_args[0])
    mkfs_args[0] = pathname
  xf = read_device_size = None
  try:
    decrypted_size = None  # is_opened will override it.
    if is_opened:  # RAWDEVICE is a dm device pathname. Needs Linux and root access.
      if decrypted_ofs is not None:
        raise UsageError('--opened conflicts with --ofs=...')
      if keytable is not None:
        raise UsageError('--opened conflicts with --keytable=...')
      if key_size is not None:
        raise UsageError('--opened conflicts with --key-size=...')
      name, expected_device_id = find_dm_crypt_device(device)
      device = None  # Don't use it accidentally.
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
      except ValueError:
        # Don't print data, it may contain the keytable.
        raise ValueError('Not a dmsetup table line.')
      if target_type != 'crypt':
        raise ValueError('target_type must be crypt, got: %r' % target_type)
      if start_sector != '0':
        # Don't print data, it may contain the keytable.
        raise ValueError('start_sector must be 0, got: %r' % stat_sector)
      try:
        sector_count = int(sector_count)
      except ValueError:
        raise ValueError('sector_count must be an integer, got: %r' % sector_count)
      if sector_count <= 0:
        raise ValueError('sector count must be positive, got: %d' % sector_count)
      decrypted_size = sector_count << 9
      try:
        keytable = keytable.decode('hex')
      except (TypeError, ValueError):
        raise ValueError('keytable must be hex, got: %s' % keytable)
      key_size = len(keytable) << 3
      cipher = sector_format
      try:
        iv_offset = int(iv_offset)
      except ValueError:
        raise ValueError('iv_ofs must be an integer, got: %r' % iv_offset)
      if iv_offset < 0:
        raise ValueError('iv_offset must be nonnegative, got: %d' % iv_offset)
      try:
        sector_offset = int(sector_offset)
      except ValueError:
        raise ValueError('sector_offset must be an integer, got: %r' % sector_offset)
      if sector_offset < 0:
        raise ValueError('sector count must be nonnegative, got: %d' % sector_offset)
      if type_value == 'luks':
        try:
          get_crypt_sectors_funcs(cipher, key_size >> 3)  # key_size can be None here, good.
        except ValueError, e:
          e = str(e)
          raise UsageError(e[:1].lower() + e[1:].rstrip('.'))
        if iv_offset != 0:
          raise ValueError('iv_offset must be 0 for --type=luks; try specifying --type=veracrypt')
      else:
        if cipher != 'aes-xts-plain64':
          raise ValueError('cipher must be aes-xts-plain64 for --type=%s, got: %r; try specifying --type=luks' % (type_value, sector_format))
        if len(keytable) != 64:
          raise ValueError('key size must be 512 for --type=%s; try specifying --type=luks' % type_value)
        if iv_offset != sector_offset:
          raise ValueError('iv_offset and sector_offset must match for --type=%s, got iv_offset=%d sector_offset=%d; try specifying --type=luks' % (type_value, iv_offset, sector_offset))
      device_id = parse_device_id(device_id)  # (major, minor)
      if expected_device_id is not None and device_id != expected_device_id:
        raise ValueError('Unexpected device_id, expecting %r, got: %r' % (expected_device_id, device_id))
      decrypted_ofs = sector_offset << 9
      device = find_device_by_id(device_id)
      if device_size == 'auto':  # Default, without --size=... flag.
        f = open(device, 'rb')
        try:
          f.seek(0, 2)
          device_size = read_device_size = f.tell()
        finally:
          f.close()
      if device_size < decrypted_ofs + decrypted_size:
        raise ValueError('Raw device too small (%d bytes) for dmsetup table: decrypted_ofs=%d decrypted_size=%d' %
                         (device_size, decrypted_ofs, decrypted_size))

      xf = DmCryptFlushingFile(
          filename=device, decrypted_filename='/dev/mapper/%s' % name,
          decrypted_ofs=decrypted_ofs, decrypted_size=decrypted_size,
          keytable=keytable, iv_ofs=iv_offset << 9)
      #xf.write('ThisIsHelloWorlF')
      #xf.seek(32)
      #xf.write('(MySecondBlock)X')

      if (device_size >> 9) < sector_offset + sector_count:
        raise ValueError('Raw device too small for encrypted volume, size: %d' % device_size)
      if type_value == 'luks':
        if decrypted_ofs < 4096:
          raise ValueError('sector_offset too small --type=luks, must be at least 8, got: %d; try specifying --type=veracrypt' % sector_offset)
        check_luks_decrypted_ofs(decrypted_ofs)
      else:
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
        if decrypted_ofs == 0:
          sys.stderr.write('warning: abort now, otherwise the first 512 bytes of %s will be overwritten, destroying filesystems such as vfat, ntfs, xfs\n' % device)

    if keytable is None:
      keytable = get_random_bytes(key_size >> 3)
    assert isinstance(keytable, str)

    if decrypted_ofs in ('fat', 'mkfat') or filesystem == 'fat1':
      if salt == '':
        do_randomize_salt = True
      elif salt == TEST_SALT:
        do_randomize_salt = False
      else:
        raise UsageError('specific --salt=... value conflicts with --ofs=fat or --mkfat=... or --filesystem=fat1')

    need_read_first = device_size == 'auto' or decrypted_ofs == 'fat'
    read_device_size = None
    if need_read_first:
      if xf is None:
        xf = open(device, 'r+b')
      if decrypted_ofs == 'fat':
        fat_header = xf.read(64)
        fatfs_size = get_fat_sizes(fat_header)[0]
        # Use --salt=test to keep the oem_id etc. intact.
        if do_randomize_salt:
          fat_header = randomize_fat_header(fat_header)
      xf.seek(0, 2)
      read_device_size = xf.tell()
      if device_size == 'auto':
        device_size = read_device_size
    assert isinstance(device_size, (int, long))

    if do_add_full_header is None:
      assert type_value != 'luks'
      if decrypted_ofs is None:
        do_add_full_header = device_size >= (4 << 20)  # 4 MiB, At most 0.4% overhead.
      else:
        do_add_full_header = decrypted_ofs not in ('fat', 'mkfat') and decrypted_ofs >= 0x20000 and device_size >= (0x20000 << bool(do_add_backup))
    if do_add_backup is None:
      do_add_backup = do_add_full_header
    if do_add_backup and not do_add_full_header:
        raise UsageError('--add-backup needs --add-full-header')
    if do_add_full_header and decrypted_ofs == 'fat':
      raise UsageError('--add-backup conflicts with --ofs=fat')
    if do_add_full_header and decrypted_ofs == 0:
      raise UsageError('--add-full-header conflicts with --ofs=0')

    decrypted_ofs_any = decrypted_ofs
    if decrypted_ofs in ('fat', 'mkfat'):
      assert isinstance(fatfs_size, (int, long))
      decrypted_ofs = fatfs_size
    elif decrypted_ofs is None:
      if type_value == 'luks':
        decrypted_ofs = get_recommended_luks_decrypted_ofs(device_size)
      else:
        decrypted_ofs = get_recommended_veracrypt_decrypted_ofs(
            device_size, do_add_full_header)
    assert isinstance(decrypted_ofs, (int, long))

    if decrypted_size is None:
      decrypted_size = device_size - decrypted_ofs - min(0x20000, decrypted_ofs) * bool(do_add_backup)
    assert isinstance(decrypted_size, (int, long))
    if type_value != 'luks' and decrypted_size < 512:
      raise UsageError('raw device too small for %s volume, minimum is %d (use --ofs=512 or --no-add-full-header to decrease), actual size: %d' %
                       (('VeraCrypt', 'TrueCrypt')[is_truecrypt], 512 + (decrypted_ofs + min(0x20000, decrypted_ofs) * bool(do_add_backup)), device_size))

    if (filesystem == 'fat1' or decrypted_ofs_any == 'mkfat') and not do_randomize_salt:
      if fat_label is None:
        fat_label = 'minifat3'
      if fat_uuid is None:
        fat_uuid = 'DEAD-BEE3'

    if decrypted_ofs_any == 'mkfat':
      fat_header = build_fat_header(
          label=fat_label, uuid=fat_uuid, fatfs_size=fatfs_size,
          fat_count=fat_fat_count,
          rootdir_entry_count=fat_rootdir_entry_count, fstype=fat_fstype,
          cluster_size=fat_cluster_size, do_randomize_salt=do_randomize_salt)

    if filesystem == 'fat1':
      fat1_header = build_fat_header(
          label=fat_label, uuid=fat_uuid, fatfs_size=decrypted_size, fstype=fat_fstype,
          rootdir_entry_count=fat_rootdir_entry_count, fat_count=fat_fat_count,
          cluster_size=fat_cluster_size, do_randomize_salt=(do_randomize_salt and decrypted_ofs == 0))
      fat1_header = build_fat_boot_sector(fat1_header, FAT_NO_BOOT_CODE)
      fatfs_size2 = get_fat_sizes(fat1_header)[0]  # Also checks fat1_header.
      if fatfs_size2 > decrypted_size:
        raise ValueError('FAT header (size %d) longer than encrypted volume (size %d).' %
                         (len(fat1_header), len(decrypted_size)))
      # TODO(pts): Use a generator (?) for sector_idx > 1 on large filesystems.
      mkfs_data = build_empty_fat(fat1_header)
      mkfs_suffix_size = len(FAT_NO_BOOT_CODE)
      assert len(mkfs_data) >= 1536
      del fat1_header
    else:
      mkfs_data = None
    def prompt_passphrase_with_warning():
      prompt_device_size = read_device_size
      if prompt_device_size is None:
        try:
          f = open(device, 'rb')
        except IOError:
          f = None
        if f:
          try:
            f.seek(0, 2)
            prompt_device_size = f.tell()
          finally:
            f.close()
      if prompt_device_size:
        if is_opened and is_quick:
          sys.stderr.write('warning: abort now, otherwise encryption headers on %s will be replaced by a new %s, old passwords will be lost, encrypted data will be kept intact\n' % (device, type_value))
        else:
          sys.stderr.write('warning: abort now, otherwise all data on %s will be lost\n' % device)
      return prompt_passphrase(do_passphrase_twice=do_passphrase_twice)

    if type_value == 'luks':
      if device_size < 2066432:  # 2018 KiB, imposed by `cryptsetup open'.
        raise UsageError('raw device too small for LUKS volume, minimum is 2066432 (2018K), actual size: %d' %
                         device_size)
      if passphrase is None:
        passphrase = prompt_passphrase_with_warning  # Callback to defer it after checks.
      enchd_backup = ''
      if cipher in ('aes-cbc-plain', 'aes-cbc-plain64'):
        # aes-cbc-plain is compatible with older Linux kernels (<= 2.6.32).
        # aes-cbc-plain64 supports decrypted_size >= 2 TiB.
        cipher2 = ('aes-cbc-plain', 'aes-cbc-plain64')[bool(decrypted_size >> 32)]
      else:
        cipher2 = cipher
      enchd = build_luks_header(
          passphrase=passphrase, decrypted_ofs=decrypted_ofs,
          uuid=uuid, pim=pim, af_stripe_count=af_stripe_count,
          hash=hash, keytable=keytable, key_size=key_size, cipher=cipher2,
          keytable_iterations=None,  # TODO(pts): Add command-line flag.
          slot_iterations=None,  # TODO(pts): Add command-line flag.
          keytable_salt=None,  # TODO(pts): Add command-line flag (--random-source=... ?)
          slot_salt=None,  # TODO(pts): Add command-line flag.
          af_salt=None,  # TODO(pts): Add command-line flag.
          )
    else:  # VeraCrypt or TrueCrypt.
      if passphrase is None:
        # Read it now, to prevent multiple prompts below.
        passphrase = prompt_passphrase_with_warning()
      is_truecrypt = type_value == 'truecrypt'
      if decrypted_ofs_any in ('fat', 'mkfat'):
        boot_sector_data = build_fat_boot_sector(fat_header, FAT_NO_BOOT_CODE)
        assert boot_sector_data.endswith(FAT_NO_BOOT_CODE)
        enchd_prefix = boot_sector_data[:64]
        enchd_suffix = FAT_NO_BOOT_CODE
      elif mkfs_data and decrypted_ofs == 0:
        enchd_prefix = crypt_aes_xts(keytable, mkfs_data[:64], do_encrypt=True, ofs=0)
        padded_mkfs_suffix = '\0' * (-mkfs_suffix_size & 15) + mkfs_data[512 - mkfs_suffix_size : 512]
        enchd_suffix = crypt_aes_xts(keytable, padded_mkfs_suffix, do_encrypt=True, ofs=512 - len(padded_mkfs_suffix))
      else:
        enchd_prefix = salt
        enchd_suffix = ''
      enchd = build_veracrypt_header(
          decrypted_size=decrypted_size, passphrase=passphrase,
          enchd_prefix=enchd_prefix, enchd_suffix=enchd_suffix,
          decrypted_ofs=decrypted_ofs, pim=pim, is_truecrypt=is_truecrypt,
          keytable=keytable, hash=hash)
      assert len(enchd) == 512
      if decrypted_ofs_any == 'mkfat':
        enchd = build_empty_fat(enchd)  # Same as enchd --> boot_sector_data.
        assert len(enchd) >= 1536
      if do_add_full_header:
        assert decrypted_ofs >= len(enchd)
        enchd += get_random_bytes(decrypted_ofs - len(enchd))
        assert len(enchd) == decrypted_ofs
      if do_add_backup:
        xofs = min(0x20000, decrypted_ofs)
        # https://www.veracrypt.fr/en/VeraCrypt%20Volume%20Format%20Specification.html
        enchd_backup = build_veracrypt_header(
            decrypted_size=device_size - decrypted_ofs - xofs,
            passphrase=passphrase, decrypted_ofs=xofs,
            enchd_prefix=salt, pim=pim, is_truecrypt=is_truecrypt,
            keytable=keytable, hash=hash)
        enchd_backup += get_random_bytes(xofs - 512)
        assert len(enchd_backup) == xofs
      else:
        enchd_backup = ''

    if not need_read_first:  # Create file if needed, check write permissions.
      open(device, 'ab').close()
    if xf is None:
      xf = open(device, 'r+b')
    xf.write(enchd)
    random_size = device_size - len(enchd) - len(enchd_backup)
    if mkfs_data and decrypted_ofs == 0:
      random_size -= len(mkfs_data) - 512
      sector_idx = 1
      aes_xts_key = get_aes_xts_codebooks(keytable)  # Cache it.
      for i in xrange(512, len(mkfs_data), 512):
        # TODO(pts): Buffer 65536 bytes for writing.
        xf.write(crypt_aes_xts(aes_xts_key, buffer(mkfs_data, i, 512), do_encrypt=True, sector_idx=sector_idx))
        sector_idx += 1
      mkfs_data = None
    if not is_quick:
      print >>sys.stderr, 'info: overwriting device with random data'
      i = random_size
      while i > 0:
        # TODO(pts): Generate faster random.
        data = get_random_bytes(min(i, 65536))
        xf.write(data)
        i -= len(data)
      if enchd_backup:
        xf.write(enchd_backup)
    elif enchd_backup:
      xf.seek(device_size - len(enchd_backup))
      xf.write(enchd_backup)
    if do_truncate:
      try:
        xf.truncate(device_size)
      except IOError:
        pass
    if mkfs_data:
      if not decrypted_ofs:
        raise ValueError('New filesystem overlaps with encrypted volume header.')
      if len(mkfs_data) & 511:
        raise ValueError('mkfs_data size must be divisible by 512, got: %d' % len(mkfs_data))
      xf.seek(decrypted_ofs)
      # TODO(pts): For DmCryptFlushingFile, avoid encryption round-trip.
      if type_value == 'luks':
        sector_idx = 0
      else:
        sector_idx = decrypted_ofs >> 9
      if cipher == 'aes-xts-plain64':
        aes_xts_key = get_aes_xts_codebooks(keytable)  # Cache it.
        for i in xrange(0, len(mkfs_data), 512):
          # TODO(pts): Buffer 65536 bytes for writing.
          xf.write(crypt_aes_xts(aes_xts_key, buffer(mkfs_data, i, 512), do_encrypt=True, sector_idx=sector_idx))
          sector_idx += 1
      else:
        crypt_sectors_func, get_codebooks_func = get_crypt_sectors_funcs(cipher)
        codebooks = get_codebooks_func(keytable)
        for i in xrange(0, len(mkfs_data), 512):
          # TODO(pts): Buffer 65536 bytes for writing.
          xf.write(crypt_sectors_func(codebooks, buffer(mkfs_data, i, 512), do_encrypt=True, sector_idx=sector_idx))
          sector_idx += 1
    if isinstance(xf, DmCryptFlushingFile):
      xf.full_flush()
    else:
      xf.flush()
      # This is useful so that changes in /dev/loop0 are copied back to DEVICE.img.
      fsync_loop_device(xf)

    if mkfs_args:
      # TODO(pts): Reuse existing dm device if is_opened.
      name = 'tinyveracrypt.mkfs.%d' % os.getpid()
      after_data_ary = []

      def block_device_callback(block_device, fd, device_id):
        table = build_table(
            keytable, decrypted_size, decrypted_ofs, device_id,
            iv_ofs=decrypted_ofs * bool(type_value != 'luks'),
            cipher='aes-xts-plain64', do_showkeys=True)
        run_and_write_stdin(('dmsetup', 'create', name), table, is_dmsetup=True)
        is_ok = False
        try:
          mkfs_args.append('/dev/mapper/%s' % name)
          if decrypted_ofs == 0:
            f = open(mkfs_args[-1], 'r+b')
            try:
              f.write('\1' * 512)  # Canary, we'll check it after mkfs.
            finally:
              f.close()
          try:
            stat_obj = os.stat(mkfs_args[-1])
          except OSError:
            stat_obj = None
          if not (stat_obj and stat.S_ISBLK(stat_obj.st_mode)):
            raise SystemExit('dm table device not found: %s' % mkfs_arg[-1])
          print >>sys.stderr, 'info: running mkfs: ' + ' '.join(map(shell_escape, mkfs_args))
          run_command(mkfs_args)
          is_ok = True
          f = open(mkfs_args[-1], 'rb')
          try:
            after_data_ary.append(f.read(512))
          finally:
            f.close()
          import time
          time.sleep(0.2)  # Avoid early race conditions in dmsetup remove.
        finally:
          # We need to retry the dmsetup remove, because other commands (e.g. udev) may be busy processing them.
          run_and_write_stdin(('dmsetup', 'remove', name), '', is_dmsetup=True, do_show_failure=is_ok, retry_count=5, retry_interval=0.5)

      ensure_block_device(device, block_device_callback)
      if decrypted_ofs == 0:
        if len(after_data_ary[0]) != 512:
          raise RuntimeError('Raw device read too short.')
        if after_data_ary[0].rstrip('\1') and after_data_ary[0].rstrip('\0'):
          # This should fire for mkfs.vfat, but not for mkfs.ext2 or mkfs.minix.
          raise RuntimeError('mkfs %r wrote unexpected value to the first 512 bytes, maybe filesystem is incompatible with --ofs=0, not writing %s header' %
                             (mkfs_args[0], ('VeraCrypt', 'TrueCrypt')[is_truecrypt]))
        xf.seek(0)
        # Write VeraCrypt header again, it was overwritten by the canary and
        # maybe mkfs.
        xf.write(enchd[:512])  # mkfs.minix has only room for 512 bytes.
        xf.flush()
        if not isinstance(xf, DmCryptFlushingFile):
          fsync_loop_device(xf)
  finally:
    if xf:
      xf.close()


def main(argv):
  passphrase = TEST_PASSPHRASE
  # !! Experiment with decrypted_ofs=0, encrypted ext2 (first 0x400 bytes are arbitrary) or reiserfs/ btrfs (first 0x10000 bytes are arbitrary) filesystem,
  #    Can we have a fake non-FAT filesystem with UUID and label? For reiserfs, set_jfs_id.py would work.
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
  #    SUXX: `fsck.ext -c ...' clears the badblocks list, so from that point on the ext{2,3,4} filesystem will be able to reuse the previous bad block
  #    There seems to be no unmovable file in ext2.
  #    btrfs (superblock at 65536) works for up to 241 GB, block size 4096, Reserved GDT blocks at 16-1024
  #    ``Reserved GDT blocks'' always finishes before 1050
  #    btrfs (superblock also at 64 MiB): To put block 32768 (64 MiB) to the
  #      ``Reserved GDT blocks'' of block group 1, we can play with `mkfs.ext4
  #      -g ...' (blocks per block group), but it may have a performance
  #      penalty on SSDs (if not aligned to 6 MB boundary); example: python -c
  #      'f = open("ext2.img", "wb"); f.truncate(240 << 30)' && mkfs.ext4 -E
  #      nodiscard -g 16304 -F ext2.img && dumpe2fs ext2.img >ext4.dump

  if len(argv) < 2:
    raise UsageError('missing command')
  if len(argv) > 1 and argv[1] == '--text':
    del argv[1]
  elif len(argv) > 2 and argv[1] == '--truecrypt' and argv[2] == '--text':
    del argv[2]
  if len(argv) > 2 and argv[1] == '--truecrypt' and argv[2] == '--create':
    argv[1 : 3] = argv[2 : 0 : -1]
  open_default_args = ('--keyfiles=', '--protect-hidden=no', '--filesystem=none', '--encryption=aes', '--custom-name')
  veracrypt_create_args = (
      '--quick', '--volume-type=normal', '--size=auto',
      '--encryption=aes', '--hash=sha512', '--filesystem=none',
      '--pim=0', '--keyfiles=',
      # '--random-source=/dev/urandom',
      '--passphrase-once')

  command = argv[1].lstrip('-')
  del argv[:2]
  if command == 'get-table':
    # Doesn't emulates: dmsetup table [--showkeys] NAME
    cmd_get_table(argv)
  elif command == 'mount':
    # Emulates: veracrypt --text --mount --keyfiles= --protect-hidden=no --pim=0 --filesystem=none --encryption=aes RAWDEVICE  # Creates /dev/mapper/veracrypt1
    # Difference: Doesn't mount a fuse filesystem (veracrypt needs sudo umount /tmp/.veracrypt_aux_mnt1; truecrypt needs sudo umount /tmp/.truecrypt_aux_mnt1)
    #
    # Creates /dev/mapper/veracrypt1 , use this to show the keytable: sudo dmsetup table --showkeys veracrypt1
    cmd_mount(argv)
  elif command == 'open':
    # Emulates: cryptsetup open --type tcrypt --veracrypt RAWDEVICE NAME  # Creates /dev/mapper/NAME
    cmd_mount(open_default_args + tuple(argv))
  elif command == 'open-table':
    cmd_open_table(argv)
  elif command in ('close', 'remove'):
    # Emulates: `cryptsetup close <device>' and `dmsetup remove <device>'.
    cmd_close(argv)
  elif command == 'create':  # For compatibility with `veracrypt --create' and `cryptsetup create' (obsolete).
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
    if len(argv) == 2 and not argv[0].startswith('-') and not argv[1].startswith('-'):
      cmd_mount(open_default_args + ('--type=plain', '--', argv[1], argv[0]))  # `cryptsetup create' (obsolete syntax).
    else:
      # Use `init --type=luks' instead for LUKS.
      cmd_create(('--restrict-type=no-luks',) + tuple(argv))
  elif command in ('luksFormat', 'luks-format'):  # For compatibility with `cryptsetup luksFormat'.
    # This is a legacy command, use `./tinyveracrypt.py init --type=luks' for better defaults.
    # `init --type=luks' is similar to: cryptsetup luksFormat --batch-mode --use-urandom --hash=sha512 --key-size=512
    # Defaults from `--hash=sha256 --key-size=256' below are from cryptsetup-1.7.3 in Debian.
    # Difference: `cryptsetup luksFormat' silently ignores `--type=tcrypt', we refuse it.
    cmd_create(veracrypt_create_args + ('--type=luks', '--hash=sha256', '--key-size=256', '--restrict-type=luks', '--restrict-luksformat-defaults') + tuple(argv))
  elif command == 'init':  # Like create, but with better (shorter) defaults.
    # Example usage: dd if=/dev/zero of=tiny.img bs=1M count=10 && ./tinyveracrypt.py init --test-passphrase --salt=test tiny.img  # Fast.
    # Example usage: dd if=/dev/zero of=tiny.img bs=1M count=10 && ./tinyveracrypt.py init --test-passphrase --ofs=fat tiny.img
    # Example usage: dd if=/dev/zero of=tiny.img bs=1M count=30 && ./tinyveracrypt.py init --test-passphrase --mkfat=24M tiny.img  # For discard (TRIM) boundary on SSDs.
    # Example usage: dd if=/dev/zero of=tiny.img bs=1M count=10 && ./tinyveracrypt.py init --test-passphrase --salt=test --mkfat=128K tiny.img  # Fast.
    cmd_create(veracrypt_create_args + ('--random-source=/dev/urandom',) + tuple(argv))
  else:
    # !! BUG: cryptsetup init 2.1.0 needs --af-stripes=4000 (since which version?); report bug
    # !! Add create --align-payload=SECTORS (for `cryptsetup luksFormat').
    # !! Add `tcryptDump' (`cryptsetup tcryptDump').
    # !! Add --help.
    # !! Add `cat' command with get_crypt_sectors_funcs, fast if root.
    # !! Add `open-fuse' command.
    # !! Add `passwd' command for changing the passphrase (root not needed). Should it also work for /dev/mapper/... or a mounted filesystem -- probably yes?
    # !! Add TrueCrypt support for aes-cbc-tcw and aes-lrw-benbi.
    # !! Not adding mode *-cbci-tcrypt, because it's not used for aes-* single cipher.
    # !! Not adding mode *-cbc-tcrypt, because it's not used for aes-* single cipher.
    # !! Add --fake-jfs-label=... and --fake-jfs-uuid=... from set_jfs_id.py.
    # !! IMPROVEMENT: cryptsetup 1.7.3: for TrueCrypt (not VeraCrypt), make hdr->d.version larger (or the other way round?, doesn't make a difference) based on minimum_version_to_extract (hdr->d.version_tc).
    # !! BUG: cryptsetup 1.7.3 open requires minimum 2018 KiB of LUKS raw device.
    # !! BUG: cryptsetup 1.7.3 tcrypt.c bug in TCRYPT_get_data_offset `if (hdr->d.version < 3) return 1;' should be `< 4' (even better: minimum_version_to_extract < 0x600), for compatibility with TrueCrypt 7.1a.
    # !! BUG: cryptsetup 1.7.3 tcrypt.c bug in TCRYPT_hdr_from_disk: `if (!hdr->d.mk_offset) hdr->d.mk_offset = 512;', this should be removed, at least for hdr->d.version >= 4, for compatibility with TrueCrypt 7.1a.
    # !! BUG: cryptsetup 1.7.3 tcrypt.c bug in TCRYPT_activate: `dmd.size = hdr->d.volume_size / hdr->d.sector_size;', should be the entire device ((device_size(crypt_metadata_device(cd), &size) < 0)) if minimum_version_to_extract < 0x600.
    raise UsageError('unknown command: %s' % command)


if __name__ == '__main__':
  try:
    sys.exit(main(sys.argv))
  except KeyboardInterrupt, e:
    try:  # Convert KeyboardInterrupt to SIGINT. Cleanups in main done.
      import signal
      os.kill
      os.getpid
      signal.signal(signal.SIGINT, signal.SIG_DFL)
    except (ImportError, OSError, AttributeError):
      raise e
    os.kill(os.getpid(), signal.SIGINT)
  except IncorrectPassphraseError, e:
    msg = str(e)
    print >>sys.stderr, 'fatal: %s%s' % (msg[:1].lower(), msg[1:].rstrip('.'))
    sys.exit(2)
  except UsageError, e:
    print >>sys.stderr, 'fatal: usage: %s' % e
    sys.exit(1)
  except SystemExit, e:
    if len(e.args) == 1 and isinstance(e.args[0], str):
      print >>sys.stderr, 'fatal: %s' % e
      sys.exit(1)
    raise
