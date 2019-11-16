#! /usr/bin/python

import sys
import os
import os.path

# Find tinyveracrypt.py.
sys.path[:0] = [os.path.join('..', os.path.dirname(__file__))]

import tinyveracrypt


def test_crypt_sectors_long():
  keytable = '07d75b79a5717605014b0f1293b0d932fb8e15974868325db28aa41aeb85c24f79580477d415368cfaa817fbd6409f13'.decode('hex')

  ciphertext = open('plain.bin', 'rb').read()

  def crypt_sectors(cipher, keytable, data, do_encrypt, sector_idx=0):
    crypt_func, get_codebooks_func = tinyveracrypt.get_crypt_sectors_funcs(cipher, len(keytable))
    codebooks = get_codebooks_func(keytable)
    return crypt_func(codebooks, data, do_encrypt, sector_idx)

  data = open('plain.exp.benbi', 'rb').read()
  assert ciphertext == crypt_sectors('aes-lrw-benbi', keytable, data, True)
  assert data == crypt_sectors('aes-lrw-benbi', keytable, ciphertext, False)

  data = open('plain.exp.plain64', 'rb').read()
  assert ciphertext == crypt_sectors('aes-lrw-plain64', keytable, data, True)
  assert data == crypt_sectors('aes-lrw-plain64', keytable, ciphertext, False)
  assert ciphertext == crypt_sectors('aes-lrw-plain', keytable, data, True)
  assert data == crypt_sectors('aes-lrw-plain', keytable, ciphertext, False)

  data = open('plain.exp.plain64be', 'rb').read()
  assert ciphertext == crypt_sectors('aes-lrw-plain64be', keytable, data, True)
  assert data == crypt_sectors('aes-lrw-plain64be', keytable, ciphertext, False)

  data = open('plain.exp.essivsha256', 'rb').read()
  assert ciphertext == crypt_sectors('aes-lrw-essiv:sha256', keytable, data, True)
  assert data == crypt_sectors('aes-lrw-essiv:sha256', keytable, ciphertext, False)

  data = open('plain.exp.cbcplain64be', 'rb').read()
  assert ciphertext == crypt_sectors('aes-cbc-plain64be', keytable[:32], data, True)
  assert data == crypt_sectors('aes-cbc-plain64be', keytable[:32], ciphertext, False)

  data = open('plain.exp.cbctcw', 'rb').read()
  assert ciphertext == crypt_sectors('aes-cbc-tcw', keytable, data, True)
  assert data == crypt_sectors('aes-cbc-tcw', keytable, ciphertext, False)


def test():
  test_crypt_sectors_long()


if __name__ == '__main__':
  os.chdir(os.path.dirname(__file__))
  test()
