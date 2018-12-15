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

class rijndael(object):
    """Helper class used by crypt_aes_xts."""

    # --- Initialize the following constants: [S, Si, T1, T2, T3, T4, T5, T6, T7, T8, U1, U2, U3, U4, num_rounds, rcon, shifts.

    shifts = [[[0, 0], [1, 3], [2, 2], [3, 1]],
              [[0, 0], [1, 5], [2, 4], [3, 3]],
              [[0, 0], [1, 7], [3, 5], [4, 4]]]

    # [keysize][block_size]
    num_rounds = {16: {16: 10, 24: 12, 32: 14}, 24: {16: 12, 24: 12, 32: 14}, 32: {16: 14, 24: 14, 32: 14}}

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

    def __init__(self, key):
        block_size = 16
        if len(key) != 16 and len(key) != 24 and len(key) != 32:
            raise ValueError('Invalid key size: ' + str(len(key)))
        self.block_size = block_size
        rcon, S, U1, U2, U3, U4 = self.rcon, self.S, self.U1, self.U2, self.U3, self.U4

        ROUNDS = self.num_rounds[len(key)][block_size]
        BC = block_size / 4
        # encryption round keys
        Ke = [[0] * BC for i in xrange(ROUNDS + 1)]
        # decryption round keys
        Kd = [[0] * BC for i in xrange(ROUNDS + 1)]
        ROUND_KEY_COUNT = (ROUNDS + 1) * BC
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
            Ke[t / BC][t % BC] = tk[j]
            Kd[ROUNDS - (t / BC)][t % BC] = tk[j]
            j += 1
            t += 1
        tt = 0
        rconpointer = 0
        while t < ROUND_KEY_COUNT:
            # extrapolate using phi (the round key evolution function)
            tt = tk[KC - 1]
            tk[0] ^= (S[(tt >> 16) & 0xFF] & 0xFF) << 24 ^  \
                     (S[(tt >>  8) & 0xFF] & 0xFF) << 16 ^  \
                     (S[ tt        & 0xFF] & 0xFF) <<  8 ^  \
                     (S[(tt >> 24) & 0xFF] & 0xFF)       ^  \
                     (rcon[rconpointer]    & 0xFF) << 24
            rconpointer += 1
            if KC != 8:
                for i in xrange(1, KC):
                    tk[i] ^= tk[i-1]
            else:
                for i in xrange(1, KC / 2):
                    tk[i] ^= tk[i-1]
                tt = tk[KC / 2 - 1]
                tk[KC / 2] ^= (S[ tt        & 0xFF] & 0xFF)       ^ \
                              (S[(tt >>  8) & 0xFF] & 0xFF) <<  8 ^ \
                              (S[(tt >> 16) & 0xFF] & 0xFF) << 16 ^ \
                              (S[(tt >> 24) & 0xFF] & 0xFF) << 24
                for i in xrange(KC / 2 + 1, KC):
                    tk[i] ^= tk[i-1]
            # copy values into round key arrays
            j = 0
            while j < KC and t < ROUND_KEY_COUNT:
                Ke[t / BC][t % BC] = tk[j]
                Kd[ROUNDS - (t / BC)][t % BC] = tk[j]
                j += 1
                t += 1
        # inverse MixColumn where needed
        for r in xrange(1, ROUNDS):
            for j in xrange(BC):
                tt = Kd[r][j]
                Kd[r][j] = U1[(tt >> 24) & 0xFF] ^ \
                           U2[(tt >> 16) & 0xFF] ^ \
                           U3[(tt >>  8) & 0xFF] ^ \
                           U4[ tt        & 0xFF]
        self.Ke = Ke
        self.Kd = Kd

    def encrypt(self, plaintext):
        if len(plaintext) != self.block_size:
            raise ValueError('wrong block length, expected ' + str(self.block_size) + ' got ' + str(len(plaintext)))
        Ke, shifts, S, T1, T2, T3, T4 = self.Ke, self.shifts, self.S, self.T1, self.T2, self.T3, self.T4

        BC = self.block_size / 4
        ROUNDS = len(Ke) - 1
        if BC == 4:
            SC = 0
        elif BC == 6:
            SC = 1
        else:
            SC = 2
        s1 = shifts[SC][1][0]
        s2 = shifts[SC][2][0]
        s3 = shifts[SC][3][0]
        a = [0] * BC
        # temporary work array
        t = []
        # plaintext to ints + key
        for i in xrange(BC):
            t.append((ord(plaintext[i * 4    ]) << 24 |
                      ord(plaintext[i * 4 + 1]) << 16 |
                      ord(plaintext[i * 4 + 2]) <<  8 |
                      ord(plaintext[i * 4 + 3])        ) ^ Ke[0][i])
        # apply round transforms
        for r in xrange(1, ROUNDS):
            for i in xrange(BC):
                a[i] = (T1[(t[ i           ] >> 24) & 0xFF] ^
                        T2[(t[(i + s1) % BC] >> 16) & 0xFF] ^
                        T3[(t[(i + s2) % BC] >>  8) & 0xFF] ^
                        T4[ t[(i + s3) % BC]        & 0xFF]  ) ^ Ke[r][i]
            t = a[:]
        # last round is special
        result = []
        for i in xrange(BC):
            tt = Ke[ROUNDS][i]
            result.append(chr((S[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF))
            result.append(chr((S[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF))
            result.append(chr((S[(t[(i + s2) % BC] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF))
            result.append(chr((S[ t[(i + s3) % BC]        & 0xFF] ^  tt       ) & 0xFF))
        return ''.join(result)

    def decrypt(self, ciphertext):
        if len(ciphertext) != self.block_size:
            raise ValueError('wrong block length, expected ' + str(self.block_size) + ' got ' + str(len(plaintext)))
        Kd, shifts, Si, T5, T6, T7, T8 = self.Kd, self.shifts, self.Si, self.T5, self.T6, self.T7, self.T8

        BC = self.block_size / 4
        ROUNDS = len(Kd) - 1
        if BC == 4:
            SC = 0
        elif BC == 6:
            SC = 1
        else:
            SC = 2
        s1 = shifts[SC][1][1]
        s2 = shifts[SC][2][1]
        s3 = shifts[SC][3][1]
        a = [0] * BC
        # temporary work array
        t = [0] * BC
        # ciphertext to ints + key
        for i in xrange(BC):
            t[i] = (ord(ciphertext[i * 4    ]) << 24 |
                    ord(ciphertext[i * 4 + 1]) << 16 |
                    ord(ciphertext[i * 4 + 2]) <<  8 |
                    ord(ciphertext[i * 4 + 3])        ) ^ Kd[0][i]
        # apply round transforms
        for r in xrange(1, ROUNDS):
            for i in xrange(BC):
                a[i] = (T5[(t[ i           ] >> 24) & 0xFF] ^
                        T6[(t[(i + s1) % BC] >> 16) & 0xFF] ^
                        T7[(t[(i + s2) % BC] >>  8) & 0xFF] ^
                        T8[ t[(i + s3) % BC]        & 0xFF]  ) ^ Kd[r][i]
            t = a[:]
        # last round is special
        result = []
        for i in xrange(BC):
            tt = Kd[ROUNDS][i]
            result.append(chr((Si[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF))
            result.append(chr((Si[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF))
            result.append(chr((Si[(t[(i + s2) % BC] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF))
            result.append(chr((Si[ t[(i + s3) % BC]        & 0xFF] ^  tt       ) & 0xFF))
        return ''.join(result)


strxor_16 = make_strxor(16)


def check_aes_xts_key(aes_xts_key):
  if len(aes_xts_key) != 64:
    raise ValueError('aes_xts_key must be 64 bytes, got: %d' % len(aes_xts_key))


# We use pure Python code (from CryptoPlus) for AES XTS encryption. This is
# slow, but it's not a problem, because we have to encrypt only 512 bytes
# per run. Please note that pycrypto-2.6.1 (released on 2013-10-17) and
# other C crypto libraries with Python bindings don't support AES XTS.
def crypt_aes_xts(aes_xts_key, data, do_encrypt):
  check_aes_xts_key(aes_xts_key)
  # This would work instead of inlining:
  #
  #   import CryptoPlus.Cipher.python_AES
  #   new_aes_xts = lambda aes_xts_key: CryptoPlus.Cipher.python_AES.new((aes_xts_key[0 : 32], aes_xts_key[32 : 64]), CryptoPlus.Cipher.python_AES.MODE_XTS)
  #   cipher = new_aes_xts(aes_xts_key)
  #   if do_encrypt:
  #     return cipher.encrypt(data)
  #   else:
  #     return cipher.decrypt(data)

  assert len(data) > 15, "At least one block of 128 bits needs to be supplied"
  assert len(data) < (1 << 27)
  do_decrypt = not do_encrypt
  codebook1, codebook2 = rijndael(aes_xts_key[0 : 32]), rijndael(aes_xts_key[32 : 64])
  codebook1_crypt = (codebook1.encrypt, codebook1.decrypt)[do_decrypt]

  # initializing T
  # e_k2_n = E_K2(tweak)
  e_k2_n = codebook2.encrypt('\0' * 16)[::-1]
  T = [int(e_k2_n.encode('hex'), 16)]

  def step(tocrypt):
    T_string = ('%032x' % T[0]).decode('hex')[::-1]
    # C = E_K1(P xor T) xor T
    return strxor_16(T_string, codebook1_crypt(strxor_16(T_string, tocrypt)))

  def T_update():
    # Used for calculating T for a certain step using the T value from the previous step
    T[0] <<= 1
    # if (Cout)
    if T[0] >> (8*16):
      #T[0] ^= GF_128_FDBK;
      T[0] ^= 0x100000000000000000000000000000087

  output = []
  i=0
  while i < ((len(data) // 16)-1): #Decrypt all the blocks but one last full block and opt one last partial block
    # C = E_K1(P xor T) xor T
    output.append(step(data[i*16:(i+1)*16]))
    # T = E_K2(n) mul (a pow i)
    T_update()
    i+=1

  # Check if the data supplied is a multiple of 16 bytes -> one last full block and we're done
  if len(data[i*16:]) == 16:
    # C = E_K1(P xor T) xor T
    output.append(step(data[i*16:(i+1)*16]))
    # T = E_K2(n) mul (a pow i)
    T_update()
  else:
    T_temp = [T[0]]
    T_update()
    T_temp.append(T[0])
    if do_decrypt:
      # Permutation of the last two indexes
      T_temp.reverse()
    # Decrypt/Encrypt the last two blocks when data is not a multiple of 16 bytes
    Cm1 = data[i*16:(i+1)*16]
    Cm = data[(i+1)*16:]
    T[0] = T_temp[0]
    PP = step(Cm1)
    Cp = PP[len(Cm):]
    Pm = PP[:len(Cm)]
    CC = Cm+Cp
    T[0] = T_temp[1]
    Pm1 = step(CC)
    output.append(Pm1)
    output.append(Pm)
  return ''.join(output)


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
  raise ImportError('Cannot find SHA512 implementation: install hashlib or pycrypto.')


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


def check_header_key(header_key):
  if len(header_key) != 64:
    raise ValueError('header_key must be 64 bytes, got: %d' % len(header_key))


def check_dechd(dechd):
  if len(dechd) != 512:
    raise ValueError('dechd must be 512 bytes, got: %d' % len(dechd))


def check_sector_size(sector_size):
  if sector_size < 512 or sector_size & (sector_size - 1):
    raise ValueError('sector_size must be a power of 2 at least 512: %d' % sector_size)


def build_dechd(salt, keytable, decrypted_size, sector_size):
  check_keytable(keytable)
  check_decrypted_size(decrypted_size)
  if len(salt) != 64:
    raise ValueError('salt must be 64 bytes, got: %d' % len(salt))
  check_sector_size(sector_size)
  version = 5
  keytablep = keytable + '\0' * 192
  keytablep_crc32 = ('%08x' % (binascii.crc32(keytablep) & 0xffffffff)).decode('hex')
  # Constants are based on what veracrypt-1.17 generates.
  header_format_version = 5
  minimum_version_to_extract = (1, 11)
  hidden_volume_size = 0
  base_offset_for_key = 0x20000
  flag_bits = 0
  # --- 0: VeraCrypt hd sector starts here
  # 0 + 64: salt
  # --- 64: header starts here
  # 64 + 4: "VERA": 56455241
  # 68 + 2: Volume header format version: 0005
  # 70 + 2: Minimum program version to open (1.11): 010b
  # 72 + 4: CRC-32 of the keytable + keytablep (decrypted bytes 256..511): ????????
  # 76 + 16: zeros: 00000000000000000000000000000000
  # 92 + 8: size of hidden volume (0 for non-hidden): 0000000000000000
  # 100 + 8: size of decrypted volume: ????????????????
  # 108 + 8: byte offset of the master key scope (always 0x20000): 0000000000020000
  # 116 + 8: size of the encrypted area within the master key scope (same as size of the decrypted volume): ????????????????
  # 124 + 4: flag bits (0): 00000000
  # 128 + 4: sector size (512 -- shouldn't it be 4096?): 00000200
  # 132 + 120: zeros: 00..00
  # --- 252: header ends here
  # 252 + 4: CRC-32 of header
  # 256 + 64: keytable (used as key by `dmsetup table' after hex-encoding)
  # 320 + 192: keytablep: zeros: 00..00
  # --- 512: VeraCrypt hd sector ends here
  header = struct.pack(
      '>4sHBB4s16xQQQQLL120x', 'VERA', header_format_version,
      minimum_version_to_extract[0], minimum_version_to_extract[1],
      keytablep_crc32, hidden_volume_size, decrypted_size,
      base_offset_for_key, decrypted_size, flag_bits, sector_size)
  assert len(header) == 188
  header_crc32 = ('%08x' % (binascii.crc32(header) & 0xffffffff)).decode('hex')
  dechd = ''.join((salt, header, header_crc32, keytablep))
  assert len(dechd) == 512
  return dechd


def check_full_dechd(dechd):
  """Does a full, after-decryption check on dechd.

  This is also used for passphrase: on a wrong passphrase, dechd is 512
  bytes of garbage.

  The checks here are more strict than what `cryptsetup' or the mount
  operation of `veracrypt' does. They can be relaxed if the need arises.
  """
  check_dechd(dechd)
  if dechd[64 : 64 + 4] != 'VERA':  # Or 'TRUE'.
    raise ValueError('Magic mismatch.')
  if dechd[72 : 76] != ('%08x' % (binascii.crc32(dechd[256 : 512]) & 0xffffffff)).decode('hex'):
    raise ValueError('keytablep_crc32 mismatch.')
  if dechd[252 : 256] != ('%08x' % (binascii.crc32(dechd[64 : 252]) & 0xffffffff)).decode('hex'):
    raise ValueError('header_crc32 mismatch.')
  header_format_version, = struct.unpack('>H', dechd[68 : 68 + 2])
  if not (5 <= header_format_version <= 9):
    raise ValueError('header_format_version mismatch.')
  minimum_version_to_extract = struct.unpack('>BB', dechd[70 : 70 + 2])
  if minimum_version_to_extract != (1, 11):
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
  base_offset_for_key, = struct.unpack('>Q', dechd[108 : 108 + 8])
  if base_offset_for_key != 0x20000:
    raise ValueError('base_offset_for_key mismatch.')
  encrypted_area_size, = struct.unpack('>Q', dechd[116 : 116 + 8])
  if encrypted_area_size != decrypted_size:
    raise ValueError('encrypted_area_size mismatch.')
  flag_bits, = struct.unpack('>L', dechd[124 : 124 + 4])
  if flag_bits:
    raise ValueError('flag_bits mismatch.')
  sector_size, = struct.unpack('>L', dechd[128 : 128 + 4])
  check_sector_size(sector_size)
  if dechd[132 : 132 + 120].lstrip('\0'):
    # Does actual VeraCrypt check this? Does cryptsetup --veracrypt check this?
    raise ValueError('Missing NUL padding at 132.')
  if dechd[256 + 64 : 512].lstrip('\0'):
    # Does actual VeraCrypt check this? Does cryptsetup --veracrypt check this?
    raise ValueError('Missing NUL padding after keytable.')


def build_table(keytable, decrypted_size, raw_device):
  check_keytable(keytable)
  check_decrypted_size(decrypted_size)
  if isinstance(raw_device, (list, tuple)):
    raw_device = '%d:%s' % tuple(raw_device)
  cipher = 'aes-xts-plain64'
  iv_offset = offset = 0x20000
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
def build_header_key(passphrase, salt_or_enchd):
  if len(salt_or_enchd) < 64:
    raise ValueError('Salt too short.')
  salt = salt_or_enchd[:64]
  iterations = 500000
  # We could use a different hash algorithm and a different iteration count.
  header_key_size = 64
  #blocksize = 16  # For MD2
  #blocksize = 64  # For MD4, MD5, RIPEMD, SHA1, SHA224, SHA256.
  #blocksize = 128  # For SHA384, SHA512.
  sha512_blocksize = 128
  return pbkdf2(passphrase, salt, header_key_size, iterations, sha512, sha512_blocksize)


def parse_dechd(dechd):
  check_dechd(dechd)
  keytable = dechd[256 : 256 + 64]
  decrypted_size, = struct.unpack('>Q', dechd[100 : 100 + 8])
  return keytable, decrypted_size


def get_table(device, passphrase, raw_device):
  enchd = open(device).read(512)
  if len(enchd) != 512:
    raise ValueError('Raw device too short for VeraCrypt header.')
  header_key = build_header_key(passphrase, enchd)  # Slow.
  dechd = decrypt_header(enchd, header_key)
  try:
    check_full_dechd(dechd)
  except ValueError, e:
    # We may put str(e) to the debug log, if requested.
    raise ValueError('Incorrect passphrase.')
  keytable, decrypted_size = parse_dechd(dechd)
  return build_table(keytable, decrypted_size, raw_device)


def main(argv):
  raw_device = '7:0'

  device = 'pp.bin'
  passphrase = 'ThisIsMyVeryLongPassphraseForMyVeraCryptVolume'

  #device = '../pts-static-cryptsetup/rr.bin'

  sys.stdout.write(get_table(device, passphrase, raw_device))
  sys.stdout.flush()


if __name__ == '__main__':
  sys.exit(main(sys.argv))
