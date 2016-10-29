#! /usr/bin/python
# by pts@fazekas.hu at Fri Oct 28 16:32:11 CEST 2016
# !! Which Python version works?

import binascii
import itertools
import struct
import sys

# ---  AES XTS crypto code.
#
# Copy-pasted from CryptoPlus (2014-11-17): https://github.com/doegox/python-cryptoplus/commit/a5a1f8aecce4ddf476b2d80b586822d9e91eeb7d
#
# !! remove comments, docstrings, unused

import random  # !! needed?
import copy
import string

def number2string(i):
    """Convert a number to a string

    Input: long or integer
    Output: string (big-endian)
    """
    s=hex(i)[2:].rstrip('L')
    if len(s) % 2:
        s = '0' + s
    return s.decode('hex')

def number2string_N(i, N):
    """Convert a number to a string of fixed size

    i: long or integer
    N: length of string
    Output: string (big-endian)
    """
    s = '%0*x' % (N*2, i)
    return s.decode('hex')

def string2number(i):
    """ Convert a string to a number

    Input: string (big-endian)
    Output: long or integer
    """
    return int(i.encode('hex'),16)

def xorstring(a,b):   # !!
    """XOR two strings of same length

    For more complex cases, see CryptoPlus.Cipher.XOR"""
    assert len(a) == len(b)
    return number2string_N(string2number(a)^string2number(b), len(a))

class Counter(str):
    #found here: http://www.lag.net/pipermail/paramiko/2008-February.txt
    """Necessary for CTR chaining mode

    Initializing a counter object (ctr = Counter('xxx'), gives a value to the counter object.
    Everytime the object is called ( ctr() ) it returns the current value and increments it by 1.
    Input/output is a raw string.

    Counter value is big endian"""
    def __init__(self, initial_ctr):
        if not isinstance(initial_ctr, str):
            raise TypeError("nonce must be str")
        self.c = int(initial_ctr.encode('hex'), 16)
    def __call__(self):
        # This might be slow, but it works as a demonstration
        ctr = ("%032x" % (self.c,)).decode('hex')
        self.c += 1
        return ctr



PAD = 0
UNPAD = 1

def bitPadding (padData, direction, length=None):
        """Pad a string using bitPadding

            padData = raw string to pad/unpad
            direction = PAD or UNPAD
            length = amount of bytes the padded string should be a multiple of
                     (length variable is not used when unpadding)
            
            returns: (un)padded raw string
            
            A new block full of padding will be added when padding data that is
            already a multiple of the length.
            
            Example:
            =========
            >>> import padding

            >>> padding.bitPadding('test', padding.PAD, 8)
            'test\\x80\\x00\\x00\\x00'
            >>> padding.bitPadding(_,padding.UNPAD)
            'test'"""
        if direction == PAD:
            if length == None:
                raise ValueError,"Supply a valid length"
            return __bitPadding(padData, length)
        elif direction == UNPAD:
            return __bitPadding_unpad(padData)
        else:
            raise ValueError,"Supply a valid direction"

def __bitPadding (toPad,length):
    padded = toPad + '\x80' + '\x00'*(length - len(toPad)%length -1)
    return padded

def __bitPadding_unpad (padded):
    if padded.rstrip('\x00')[-1] == '\x80':
        return padded.rstrip('\x00')[:-1]
    else:
        return padded

def zerosPadding (padData, direction, length=None):
        """Pad a string using zerosPadding

            padData = raw string to pad/unpad
            direction = PAD or UNPAD
                        beware: padding and unpadding a string ending in 0's
                                will remove those 0's too
            length = amount of bytes the padded string should be a multiple of
                     (length variable is not used when unpadding)
            
            returns: (un)padded raw string
            
            No padding will be added when padding data that is already a
            multiple of the given length.
            
            Example:
            =========
            >>> import padding

            >>> padding.zerosPadding('12345678',padding.PAD,16)
            '12345678\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
            >>> padding.zerosPadding(_,padding.UNPAD)
            '12345678'"""
        if direction == PAD:
            if length == None:
                raise ValueError,"Supply a valid length"
            return __zerosPadding(padData, length)
        elif direction == UNPAD:
            return __zerosPadding_unpad(padData)
        else:
            raise ValueError,"Supply a valid direction"

def __zerosPadding (toPad, length):
    padLength = (length - len(toPad))%length
    return toPad + '\x00'*padLength

def __zerosPadding_unpad (padded ):
    return padded.rstrip('\x00')

def PKCS7(padData, direction, length=None):
        """Pad a string using PKCS7

            padData = raw string to pad/unpad
            direction = PAD or UNPAD
            length = amount of bytes the padded string should be a multiple of
                     (length variable is not used when unpadding)
            
            returns: (un)padded raw string
            
            A new block full of padding will be added when padding data that is
            already a multiple of the given length.
            
            Example:
            =========
            >>> import padding

            >>> padding.PKCS7('12345678',padding.PAD,16)
            '12345678\\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08'
            >>> padding.PKCS7(_,padding.UNPAD)
            '12345678'"""
        if direction == PAD:
            if length == None:
                raise ValueError,"Supply a valid length"
            return __PKCS7(padData, length)
        elif direction == UNPAD:
            return __PKCS7_unpad(padData)
        else:
            raise ValueError,"Supply a valid direction"


def __PKCS7 (toPad, length):
    amount = length - len(toPad)%length
    pattern = chr(amount)
    pad = pattern*amount
    return toPad + pad

def __PKCS7_unpad (padded):
    pattern = padded[-1]
    length = ord(pattern)
    #check if the bytes to be removed are all the same pattern
    if padded.endswith(pattern*length):
        return padded[:-length]
    else:
        return padded
        print 'error: padding pattern not recognized'

def ANSI_X923 (padData, direction, length=None):
        """Pad a string using ANSI_X923

            padData = raw string to pad/unpad
            direction = PAD or UNPAD
            length = amount of bytes the padded string should be a multiple of
                     (length variable is not used when unpadding)
            
            returns: (un)padded raw string
            
            A new block full of padding will be added when padding data that is
            already a multiple of the given length.
            
            Example:
            =========
            >>> import padding
            
            >>> padding.ANSI_X923('12345678',padding.PAD,16)
            '12345678\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x08'
            >>> padding.ANSI_X923(_,padding.UNPAD)
            '12345678'"""
        if direction == PAD:
            if length == None:
                raise ValueError,"Supply a valid length"
            return __ANSI_X923(padData, length)
        elif direction == UNPAD:
            return __ANSI_X923_unpad(padData)
        else:
            raise ValueError,"Supply a valid direction"

def __ANSI_X923 (toPad, length):
    bytesToPad = length - len(toPad)%length
    trail = chr(bytesToPad)
    pattern = '\x00'*(bytesToPad -1) + trail
    return toPad + pattern

def __ANSI_X923_unpad (padded):
    length =ord(padded[-1])
    #check if the bytes to be removed are all zero
    if padded.count('\x00',-length,-1) == length - 1:
        return padded[:-length]
    else:
        print 'error: padding pattern not recognized %s' % padded.count('\x00',-length,-1)
        return padded

def ISO_10126 (padData, direction, length=None):
        """Pad a string using ISO_10126

            padData = raw string to pad/unpad
            direction = PAD or UNPAD
            length = amount of bytes the padded string should be a multiple of
                     (length variable is not used when unpadding)
            
            returns: (un)padded raw string
            
            A new block full of padding will be added when padding data that is
            already a multiple of the given length.
            
            Example:
            =========
            >>> import padding

            >>> padded = padding.ISO_10126('12345678',padding.PAD,16)
            >>> padding.ISO_10126(padded,padding.UNPAD)
            '12345678'"""
        if direction == PAD:
            if length == None:
                raise ValueError,"Supply a valid length"
            return __ISO_10126(padData, length)
        elif direction == UNPAD:
            return __ISO_10126_unpad(padData)
        else:
            raise ValueError,"Supply a valid direction"

def __ISO_10126 (toPad, length):
    bytesToPad = length - len(toPad)%length
    randomPattern = ''.join(chr(random.randint(0,255)) for x in range(0,bytesToPad-1))
    return toPad + randomPattern + chr(bytesToPad)

def __ISO_10126_unpad (padded):
   return padded[0:len(padded)-ord(padded[-1])]

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_XTS = 7
MODE_CMAC = 8

class BlockCipher():
    """ Base class for all blockciphers
    """

    key_error_message = "Wrong key size" #should be overwritten in child classes

    def __init__(self,key,mode,IV,counter,cipher_module,segment_size,args={}):
        # Cipher classes inheriting from this one take care of:
        #   self.blocksize
        #   self.cipher
        self.key = key
        self.mode = mode
        self.cache = ''
        self.ed = None

        if 'keylen_valid' in dir(self): #wrappers for pycrypto functions don't have this function
         if not self.keylen_valid(key) and type(key) is not tuple:
                raise ValueError(self.key_error_message)

        if IV == None:
            self.IV = '\x00'*self.blocksize
        else:
            self.IV = IV

        if mode <> MODE_XTS:
            self.cipher = cipher_module(self.key,**args)
        if mode == MODE_ECB:
            self.chain = ECB(self.cipher, self.blocksize)
        elif mode == MODE_CBC:
            if len(self.IV) <> self.blocksize:
                raise Exception,"the IV length should be %i bytes"%self.blocksize
            self.chain = CBC(self.cipher, self.blocksize,self.IV)
        elif mode == MODE_CFB:
            if len(self.IV) <> self.blocksize:
                raise Exception,"the IV length should be %i bytes"%self.blocksize
            if segment_size == None:
                raise ValueError,"segment size must be defined explicitely for CFB mode"
            if segment_size > self.blocksize*8 or segment_size%8 <> 0:
                # current CFB implementation doesn't support bit level acces => segment_size should be multiple of bytes
                raise ValueError,"segment size should be a multiple of 8 bits between 8 and %i"%(self.blocksize*8)
            self.chain = CFB(self.cipher, self.blocksize,self.IV,segment_size)
        elif mode == MODE_OFB:
            if len(self.IV) <> self.blocksize:
                raise ValueError("the IV length should be %i bytes"%self.blocksize)
            self.chain = OFB(self.cipher, self.blocksize,self.IV)
        elif mode == MODE_CTR:
            if (counter == None) or  not callable(counter):
                raise Exception,"Supply a valid counter object for the CTR mode"
            self.chain = CTR(self.cipher,self.blocksize,counter)
        elif mode == MODE_XTS:
            if self.blocksize <> 16:
                raise Exception,'XTS only works with blockcipher that have a 128-bit blocksize'
            if not(type(key) == tuple and len(key) == 2):
                raise Exception,'Supply two keys as a tuple when using XTS'
            if 'keylen_valid' in dir(self): #wrappers for pycrypto functions don't have this function
             if not self.keylen_valid(key[0]) or  not self.keylen_valid(key[1]):
                raise ValueError(self.key_error_message)
            self.cipher = cipher_module(self.key[0],**args)
            self.cipher2 = cipher_module(self.key[1],**args)
            self.chain = XTS(self.cipher, self.cipher2)
        elif mode == MODE_CMAC:
            if self.blocksize not in (8,16):
                raise Exception,'CMAC only works with blockcipher that have a 64 or 128-bit blocksize'
            self.chain = CMAC(self.cipher,self.blocksize,self.IV)
        else:
                raise Exception,"Unknown chaining mode!"

    def encrypt(self,plaintext,n=''):
        """Encrypt some plaintext

            plaintext   = a string of binary data
            n           = the 'tweak' value when the chaining mode is XTS

        The encrypt function will encrypt the supplied plaintext.
        The behavior varies slightly depending on the chaining mode.

        ECB, CBC:
        ---------
        When the supplied plaintext is not a multiple of the blocksize
          of the cipher, then the remaining plaintext will be cached.
        The next time the encrypt function is called with some plaintext,
          the new plaintext will be concatenated to the cache and then
          cache+plaintext will be encrypted.

        CFB, OFB, CTR:
        --------------
        When the chaining mode allows the cipher to act as a stream cipher,
          the encrypt function will always encrypt all of the supplied
          plaintext immediately. No cache will be kept.

        XTS:
        ----
        Because the handling of the last two blocks is linked,
          it needs the whole block of plaintext to be supplied at once.
        Every encrypt function called on a XTS cipher will output
          an encrypted block based on the current supplied plaintext block.

        CMAC:
        -----
        Everytime the function is called, the hash from the input data is calculated.
        No finalizing needed.
        The hashlength is equal to block size of the used block cipher.
        """
        #self.ed = 'e' if chain is encrypting, 'd' if decrypting,
        # None if nothing happened with the chain yet
        #assert self.ed in ('e',None) 
        # makes sure you don't encrypt with a cipher that has started decrypting
        self.ed = 'e'
        if self.mode == MODE_XTS:
            # data sequence number (or 'tweak') has to be provided when in XTS mode
            return self.chain.update(plaintext,'e',n)
        else:
            return self.chain.update(plaintext,'e')

    def decrypt(self,ciphertext,n=''):
        """Decrypt some ciphertext

            ciphertext  = a string of binary data
            n           = the 'tweak' value when the chaining mode is XTS

        The decrypt function will decrypt the supplied ciphertext.
        The behavior varies slightly depending on the chaining mode.

        ECB, CBC:
        ---------
        When the supplied ciphertext is not a multiple of the blocksize
          of the cipher, then the remaining ciphertext will be cached.
        The next time the decrypt function is called with some ciphertext,
          the new ciphertext will be concatenated to the cache and then
          cache+ciphertext will be decrypted.

        CFB, OFB, CTR:
        --------------
        When the chaining mode allows the cipher to act as a stream cipher,
          the decrypt function will always decrypt all of the supplied
          ciphertext immediately. No cache will be kept.

        XTS:
        ----
        Because the handling of the last two blocks is linked,
          it needs the whole block of ciphertext to be supplied at once.
        Every decrypt function called on a XTS cipher will output
          a decrypted block based on the current supplied ciphertext block.

        CMAC:
        -----
        Mode not supported for decryption as this does not make sense.
        """
        #self.ed = 'e' if chain is encrypting, 'd' if decrypting,
        # None if nothing happened with the chain yet
        #assert self.ed in ('d',None)
        # makes sure you don't decrypt with a cipher that has started encrypting
        self.ed = 'd'
        if self.mode == MODE_XTS:
            # data sequence number (or 'tweak') has to be provided when in XTS mode
            return self.chain.update(ciphertext,'d',n)
        else:
            return self.chain.update(ciphertext,'d')

    def final(self,padfct=PKCS7):
        # TODO: after calling final, reset the IV? so the cipher is as good as new?
        """Finalizes the encryption by padding the cache

            padfct = padding function
                     import from CryptoPlus.Util.padding

        For ECB, CBC: the remaining bytes in the cache will be padded and
                      encrypted.
        For OFB,CFB, CTR: an encrypted padding will be returned, making the
                          total outputed bytes since construction of the cipher
                          a multiple of the blocksize of that cipher.

        If the cipher has been used for decryption, the final function won't do
          anything. You have to manually unpad if necessary.

        After finalization, the chain can still be used but the IV, counter etc
          aren't reset but just continue as they were after the last step (finalization step).
        """
        assert self.mode not in (MODE_XTS, MODE_CMAC) # finalizing (=padding) doesn't make sense when in XTS or CMAC mode
        if self.ed == 'e':
            # when the chain is in encryption mode, finalizing will pad the cache and encrypt this last block
            if self.mode in (MODE_OFB,MODE_CFB,MODE_CTR):
                dummy = '0'*(self.chain.totalbytes%self.blocksize) # a dummy string that will be used to get a valid padding
            else: #ECB, CBC
                dummy = self.chain.cache
            pad = padfct(dummy,PAD,self.blocksize)[len(dummy):] # construct the padding necessary
            return self.chain.update(pad,'e') # supply the padding to the update function => chain cache will be "cache+padding"
        else:
            # final function doesn't make sense when decrypting => padding should be removed manually
            pass

class ECB:
    """ECB chaining mode
    """
    def __init__(self, codebook, blocksize):
        self.cache = ''
        self.codebook = codebook
        self.blocksize = blocksize

    def update(self, data, ed):
        """Processes the given ciphertext/plaintext

        Inputs:
            data: raw string of any length
            ed:   'e' for encryption, 'd' for decryption
        Output:
            processed raw string block(s), if any

        When the supplied data is not a multiple of the blocksize
          of the cipher, then the remaining input data will be cached.
        The next time the update function is called with some data,
          the new data will be concatenated to the cache and then
          cache+data will be processed and full blocks will be outputted.
        """
        output_blocks = []
        self.cache += data
        if len(self.cache) < self.blocksize:
            return ''
        for i in xrange(0, len(self.cache)-self.blocksize+1, self.blocksize):
            #the only difference between encryption/decryption in the chain is the cipher block
            if ed == 'e':
                output_blocks.append(self.codebook.encrypt( self.cache[i:i + self.blocksize] ))
            else:
                output_blocks.append(self.codebook.decrypt( self.cache[i:i + self.blocksize] ))
        self.cache = self.cache[i+self.blocksize:]
        return ''.join(output_blocks)

class CBC:
    """CBC chaining mode
    """
    def __init__(self, codebook, blocksize, IV):
        self.IV = IV
        self.cache = ''
        self.codebook = codebook
        self.blocksize = blocksize

    def update(self, data, ed):
        """Processes the given ciphertext/plaintext

        Inputs:
            data: raw string of any length
            ed:   'e' for encryption, 'd' for decryption
        Output:
            processed raw string block(s), if any

        When the supplied data is not a multiple of the blocksize
          of the cipher, then the remaining input data will be cached.
        The next time the update function is called with some data,
          the new data will be concatenated to the cache and then
          cache+data will be processed and full blocks will be outputted.
        """
        if ed == 'e':
            encrypted_blocks = ''
            self.cache += data
            if len(self.cache) < self.blocksize:
                return ''
            for i in xrange(0, len(self.cache)-self.blocksize+1, self.blocksize):
                self.IV = self.codebook.encrypt(xorstring(self.cache[i:i+self.blocksize],self.IV))
                encrypted_blocks += self.IV
            self.cache = self.cache[i+self.blocksize:]
            return encrypted_blocks
        else:
            decrypted_blocks = ''
            self.cache += data
            if len(self.cache) < self.blocksize:
                return ''
            for i in xrange(0, len(self.cache)-self.blocksize+1, self.blocksize):
                plaintext = xorstring(self.IV,self.codebook.decrypt(self.cache[i:i + self.blocksize]))
                self.IV = self.cache[i:i + self.blocksize]
                decrypted_blocks+=plaintext
            self.cache = self.cache[i+self.blocksize:]
            return decrypted_blocks

class CFB:
    # TODO: bit access instead of only byte level access
    """CFB Chaining Mode

    Can be accessed as a stream cipher.
    """

    def __init__(self, codebook, blocksize, IV,segment_size):
        self.codebook = codebook
        self.IV = IV
        self.blocksize = blocksize
        self.segment_size = segment_size/8
        self.keystream = []
        self.totalbytes = 0
        
    def update(self, data, ed):
        """Processes the given ciphertext/plaintext

        Inputs:
            data: raw string of any multiple of bytes
            ed:   'e' for encryption, 'd' for decryption
        Output:
            processed raw string

        The encrypt/decrypt functions will always process all of the supplied
          input data immediately. No cache will be kept.
        """
        output = list(data)

        for i in xrange(len(data)):
            if ed =='e':
                if len(self.keystream) == 0:
                    block = self.codebook.encrypt(self.IV)
                    self.keystream = list(block)[:self.segment_size] # keystream consists of the s MSB's
                    self.IV = self.IV[self.segment_size:] # keeping (b-s) LSB's
                output[i] = chr(ord(output[i]) ^ ord(self.keystream.pop(0)))
                self.IV += output[i] # the IV for the next block in the chain is being built byte per byte as the ciphertext flows in
            else:
                if len(self.keystream) == 0:
                    block = self.codebook.encrypt(self.IV)
                    self.keystream = list(block)[:self.segment_size]
                    self.IV = self.IV[self.segment_size:]
                self.IV += output[i]
                output[i] = chr(ord(output[i]) ^ ord(self.keystream.pop(0)))
        self.totalbytes += len(output)
        return ''.join(output)

class OFB:
    """OFB Chaining Mode

    Can be accessed as a stream cipher.
    """
    def __init__(self, codebook, blocksize, IV):
        self.codebook = codebook
        self.IV = IV
        self.blocksize = blocksize
        self.keystream = []
        self.totalbytes = 0
        
    def update(self, data, ed):
        """Processes the given ciphertext/plaintext

        Inputs:
            data: raw string of any multiple of bytes
            ed:   'e' for encryption, 'd' for decryption
        Output:
            processed raw string

        The encrypt/decrypt functions will always process all of the supplied
          input data immediately. No cache will be kept.
        """
        #no difference between encryption and decryption mode
        n = len(data)
        blocksize = self.blocksize
        output = list(data)

        for i in xrange(n):
            if len(self.keystream) == 0: #encrypt a new counter block when the current keystream is fully used
                self.IV = self.codebook.encrypt(self.IV)
                self.keystream = list(self.IV)
            output[i] = chr(ord(output[i]) ^ ord(self.keystream.pop(0))) #as long as an encrypted counter value is available, the output is just "input XOR keystream"
        
        self.totalbytes += len(output)
        return ''.join(output)

class CTR:
    """CTR Chaining Mode

    Can be accessed as a stream cipher.
    """
    # initial counter value can be choosen, decryption always starts from beginning
    #   -> you can start from anywhere yourself: just feed the cipher encoded blocks and feed a counter with the corresponding value
    def __init__(self, codebook, blocksize, counter):
        self.codebook = codebook
        self.counter = counter
        self.blocksize = blocksize
        self.keystream = [] #holds the output of the current encrypted counter value
        self.totalbytes = 0

    def update(self, data, ed):
        """Processes the given ciphertext/plaintext

        Inputs:
            data: raw string of any multiple of bytes
            ed:   'e' for encryption, 'd' for decryption
        Output:
            processed raw string

        The encrypt/decrypt functions will always process all of the supplied
          input data immediately. No cache will be kept.
        """
        # no need for the encryption/decryption distinction: both are the same
        n = len(data)
        blocksize = self.blocksize

        output = list(data)
        for i in xrange(n):
            if len(self.keystream) == 0: #encrypt a new counter block when the current keystream is fully used
                block = self.codebook.encrypt(self.counter())
                self.keystream = list(block)
            output[i] = chr(ord(output[i])^ord(self.keystream.pop(0))) #as long as an encrypted counter value is available, the output is just "input XOR keystream"
        self.totalbytes += len(output)
        return ''.join(output)

class XTS:
    """XTS Chaining Mode
    
    Usable with blockciphers with a 16-byte blocksize
    """
    # TODO: allow other blocksizes besides 16bytes?
    def __init__(self,codebook1, codebook2):
        self.cache = ''
        self.codebook1 = codebook1
        self.codebook2 = codebook2

    def update(self, data, ed,tweak=''):
        # supply n as a raw string
        # tweak = data sequence number
        """Perform a XTS encrypt/decrypt operation.

        Because the handling of the last two blocks is linked,
          it needs the whole block of ciphertext to be supplied at once.
        Every decrypt function called on a XTS cipher will output
          a decrypted block based on the current supplied ciphertext block.
        """
        output = ''
        assert len(data) > 15, "At least one block of 128 bits needs to be supplied"
        assert len(data) < 128*pow(2,20)

        # initializing T
        # e_k2_n = E_K2(tweak)
        e_k2_n = self.codebook2.encrypt(tweak+ '\x00' * (16-len(tweak)))[::-1]
        self.T = string2number(e_k2_n)

        i=0
        while i < ((len(data) // 16)-1): #Decrypt all the blocks but one last full block and opt one last partial block
            # C = E_K1(P xor T) xor T
            output += self.__xts_step(ed,data[i*16:(i+1)*16],self.T)
            # T = E_K2(n) mul (a pow i)
            self.__T_update()
            i+=1

        # Check if the data supplied is a multiple of 16 bytes -> one last full block and we're done
        if len(data[i*16:]) == 16:
            # C = E_K1(P xor T) xor T
            output += self.__xts_step(ed,data[i*16:(i+1)*16],self.T)
            # T = E_K2(n) mul (a pow i)
            self.__T_update()
        else:
            T_temp = [self.T]
            self.__T_update()
            T_temp.append(self.T)
            if ed=='d':
                # Permutation of the last two indexes
                T_temp.reverse()
            # Decrypt/Encrypt the last two blocks when data is not a multiple of 16 bytes
            Cm1 = data[i*16:(i+1)*16]
            Cm = data[(i+1)*16:]
            PP = self.__xts_step(ed,Cm1,T_temp[0])
            Cp = PP[len(Cm):]
            Pm = PP[:len(Cm)]
            CC = Cm+Cp
            Pm1 = self.__xts_step(ed,CC,T_temp[1])
            output += Pm1 + Pm
        return output

    def __xts_step(self,ed,tocrypt,T):
        T_string = number2string_N(T,16)[::-1]
        # C = E_K1(P xor T) xor T
        if ed == 'd':
            return xorstring(T_string, self.codebook1.decrypt(xorstring(T_string, tocrypt)))
        else:
            return xorstring(T_string, self.codebook1.encrypt(xorstring(T_string, tocrypt)))

    def __T_update(self):
        # Used for calculating T for a certain step using the T value from the previous step
        self.T = self.T << 1
        # if (Cout)
        if self.T >> (8*16):
            #T[0] ^= GF_128_FDBK;
            self.T = self.T ^ 0x100000000000000000000000000000087L


class CMAC:
    """CMAC chaining mode

    Supports every cipher with a blocksize available
      in the list CMAC.supported_blocksizes.
    The hashlength is equal to block size of the used block cipher.
    
    Usable with blockciphers with a 8 or 16-byte blocksize
    """
    # TODO: move to hash module?
    # TODO: change update behaviour to .update() and .digest() as for all hash modules?
    #       -> other hash functions in pycrypto: calling update, concatenates current input with previous input and hashes everything
    __Rb_dictionary = {64:0x000000000000001b,128:0x00000000000000000000000000000087}
    supported_blocksizes = __Rb_dictionary.keys()
    def __init__(self,codebook,blocksize,IV):
        # Purpose of init: calculate Lu & Lu2
        #blocksize (in bytes): to select the Rb constant in the dictionary
        #Rb as a dictionary: adding support for other blocksizes is easy
        self.cache=''
        self.blocksize = blocksize
        self.codebook = codebook
        self.IV = IV

        #Rb_dictionary: holds values for Rb for different blocksizes
        # values for 64 and 128 bits found here: http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
        # explanation from: http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
        #             Rb is a representation of a certain irreducible binary polynomial of degree b, namely,
        #             the lexicographically first among all such polynomials with the minimum possible number of
        #             nonzero terms. If this polynomial is expressed as ub+cb-1ub-1+...+c2u2+c1u+c0, where the
        #             coefficients cb-1, cb-2, ..., c2, c1, c0 are either 0 or 1, then Rb is the bit string cb-1cb-2...c2c1c0.

        self.Rb = self.__Rb_dictionary[blocksize*8]

        mask1 = int(('\xff'*blocksize).encode('hex'),16)
        mask2 = int(('\x80' + '\x00'*(blocksize-1) ).encode('hex'),16)

        L = int(self.codebook.encrypt('\x00'*blocksize).encode('hex'),16)

        if L & mask2:
            Lu = ((L << 1) & mask1) ^ self.Rb
        else:
            Lu = L << 1
            Lu = Lu & mask1

        if Lu & mask2:
            Lu2 = ((Lu << 1) & mask1)^ self.Rb
        else:
            Lu2 = Lu << 1
            Lu2 = Lu2 & mask1

        self.Lu =number2string_N(Lu,self.blocksize)
        self.Lu2=number2string_N(Lu2,self.blocksize)

    def update(self, data, ed):
        """Processes the given ciphertext/plaintext

        Inputs:
            data: raw string of any length
            ed:   'e' for encryption, 'd' for decryption
        Output:
            hashed data as raw string

        This is not really an update function:
        Everytime the function is called, the hash from the input data is calculated.
        No finalizing needed.
        """
        assert ed == 'e'
        blocksize = self.blocksize

        m = (len(data)+blocksize-1)/blocksize #m = amount of datablocks
        i=0
        for i in range(1,m):
            self.IV = self.codebook.encrypt(xorstring(data[(i-1)*blocksize:(i)*blocksize],self.IV) )

        if len(data[(i)*blocksize:])==blocksize:
            X = xorstring(xorstring(data[(i)*blocksize:],self.IV),self.Lu)
        else:
            tmp = data[(i)*blocksize:] + '\x80' + '\x00'*(blocksize - len(data[(i)*blocksize:])-1)
            X = xorstring(xorstring(tmp,self.IV),self.Lu2)

        T = self.codebook.encrypt(X)
        return T


# !!!

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
def mul(a, b):
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
                AA[t][j] ^= mul(AA[i][j], AA[t][i])
            AA[t][i] = 0

iG = [[0] * 4 for i in xrange(4)]

for i in xrange(4):
    for j in xrange(4):
        iG[i][j] = AA[i][j + 4]

def mul4(a, bs):
    if a == 0:
        return 0
    r = 0
    for b in bs:
        r <<= 8
        if b != 0:
            r = r | mul(a, b)
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
    T1.append(mul4(s, G[0]))
    T2.append(mul4(s, G[1]))
    T3.append(mul4(s, G[2]))
    T4.append(mul4(s, G[3]))

    s = Si[t]
    T5.append(mul4(s, iG[0]))
    T6.append(mul4(s, iG[1]))
    T7.append(mul4(s, iG[2]))
    T8.append(mul4(s, iG[3]))

    U1.append(mul4(t, iG[0]))
    U2.append(mul4(t, iG[1]))
    U3.append(mul4(t, iG[2]))
    U4.append(mul4(t, iG[3]))

# round constants
rcon = [1]
r = 1
for t in xrange(1, 30):
    r = mul(2, r)
    rcon.append(r)

del A
del AA
del pivot
del B
del G
del box
del log
del alog
del i
del j
del r
del s
del t
del mul
del mul4
del cox
del iG

class rijndael:
    def __init__(self, key, block_size = 16):
        if block_size != 16 and block_size != 24 and block_size != 32:
            raise ValueError('Invalid block size: ' + str(block_size))
        if len(key) != 16 and len(key) != 24 and len(key) != 32:
            raise ValueError('Invalid key size: ' + str(len(key)))
        self.block_size = block_size

        ROUNDS = num_rounds[len(key)][block_size]
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
        Ke = self.Ke

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
            t = copy.copy(a)
        # last round is special
        result = []
        for i in xrange(BC):
            tt = Ke[ROUNDS][i]
            result.append((S[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((S[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((S[(t[(i + s2) % BC] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF)
            result.append((S[ t[(i + s3) % BC]        & 0xFF] ^  tt       ) & 0xFF)
        return string.join(map(chr, result), '')

    def decrypt(self, ciphertext):
        if len(ciphertext) != self.block_size:
            raise ValueError('wrong block length, expected ' + str(self.block_size) + ' got ' + str(len(plaintext)))
        Kd = self.Kd

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
            t = copy.copy(a)
        # last round is special
        result = []
        for i in xrange(BC):
            tt = Kd[ROUNDS][i]
            result.append((Si[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((Si[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((Si[(t[(i + s2) % BC] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF)
            result.append((Si[ t[(i + s3) % BC]        & 0xFF] ^  tt       ) & 0xFF)
        return string.join(map(chr, result), '')

def encrypt(key, block):
    return rijndael(key, len(block)).encrypt(block)

def decrypt(key, block):
    return rijndael(key, len(block)).decrypt(block)


def AES_new(key,mode=MODE_ECB,IV=None,counter=None,segment_size=None):
    """Create a new cipher object

    Wrapper for pure python implementation rijndael.py

        key = raw string containing the key, AES-128..256 will be selected according to the key length
            -> when using XTS mode: the key should be a tuple containing the 2 keys needed
        mode = python_AES.MODE_ECB/CBC/CFB/OFB/CTR/XTS/CMAC, default is ECB
            -> for every mode, except ECB and CTR, it is important to construct a seperate cipher for encryption and decryption
        IV = IV as a raw string, default is "all zero" IV
            -> needed for CBC, CFB and OFB mode
        counter = counter object (Counter)
            -> only needed for CTR mode
            -> use a seperate counter object for the cipher and decipher: the counter is updated directly, not a copy
                see CTR example further on in the docstring
        segment_size = amount of bits to use from the keystream in each chain part
            -> supported values: multiple of 8 between 8 and the blocksize
               of the cipher (only per byte access possible), default is 8
            -> only needed for CFB mode

    Notes:
        - Always construct a seperate cipher object for encryption and decryption. Once a cipher object has been used for encryption,
          it can't be used for decryption because it keeps a state (if necessary) for the IV.

    EXAMPLES:
    **********
    IMPORTING:
    -----------
    >>> from CryptoPlus.Cipher import python_AES

    ECB EXAMPLE:
    -------------
    NIST Special Publication 800-38A http://cryptome.org/bcm/sp800-38a.htm#F

    >>> cipher = python_AES.new('2b7e151628aed2a6abf7158809cf4f3c'.decode('hex'))
    >>> crypted = cipher.encrypt('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'.decode('hex'))
    >>> crypted.encode('hex')
    '3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf'
    >>> decipher = python_AES.new('2b7e151628aed2a6abf7158809cf4f3c'.decode('hex'))
    >>> decipher.decrypt(crypted).encode('hex')
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'

    PADDING EXAMPLE:
    -----------------
    >>> cipher = python_AES.new('0123456789012345')
    >>> crypt = cipher.encrypt('0123456789012')
    >>> crypt += cipher.final()
    >>> decipher = python_AES.new('0123456789012345')
    >>> decipher.decrypt(crypt)
    '0123456789012\\x03\\x03\\x03'

    CBC EXAMPLE (plaintext = 3 blocksizes):
    -----------------------------------------
    NIST Special Publication 800-38A http://cryptome.org/bcm/sp800-38a.htm#F

    >>> key = ('2b7e151628aed2a6abf7158809cf4f3c').decode('hex')
    >>> IV = ('000102030405060708090a0b0c0d0e0f').decode('hex')
    >>> plaintext1 = ('6bc1bee22e409f96e93d7e117393172a').decode('hex')
    >>> plaintext2 = ('ae2d8a571e03ac9c9eb76fac45af8e51').decode('hex')
    >>> plaintext3 = ('30c81c46a35ce411e5fbc1191a0a52ef').decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_CBC,IV)
    >>> ciphertext = cipher.encrypt(plaintext1 + plaintext2 + plaintext3)
    >>> (ciphertext).encode('hex')
    '7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e22229516'
    >>> decipher = python_AES.new(key,python_AES.MODE_CBC,IV)
    >>> plaintext = decipher.decrypt(ciphertext)
    >>> (plaintext).encode('hex')
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef'

    OR: supply plaintext as seperate pieces:
    ------------------------------------------
    >>> cipher = python_AES.new(key,python_AES.MODE_CBC,IV)
    >>> ( cipher.encrypt(plaintext1 + plaintext2[:-2]) ).encode('hex')
    '7649abac8119b246cee98e9b12e9197d'
    >>> ( cipher.encrypt(plaintext2[-2:] + plaintext3) ).encode('hex')
    '5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e22229516'
    >>> decipher = python_AES.new(key,python_AES.MODE_CBC,IV)
    >>> (decipher.decrypt(ciphertext[:22])).encode('hex')
    '6bc1bee22e409f96e93d7e117393172a'
    >>> (decipher.decrypt(ciphertext[22:])).encode('hex')
    'ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef'

    CFB EXAMPLE: (CFB8-AES192)
    ------------
    NIST Special Publication 800-38A http://cryptome.org/bcm/sp800-38a.htm#F
    
    >>> key = '2b7e151628aed2a6abf7158809cf4f3c'.decode('hex')
    >>> IV = '000102030405060708090a0b0c0d0e0f'.decode('hex')
    >>> plain = '6bc1bee22e409f96e93d7e117393172a'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_CFB,IV=IV,segment_size=8)
    >>> ciphertext = cipher.encrypt(plain)
    >>> ciphertext.encode('hex')
    '3b79424c9c0dd436bace9e0ed4586a4f'
    >>> decipher = python_AES.new(key,python_AES.MODE_CFB,IV)
    >>> decipher.decrypt(ciphertext).encode('hex')
    '6bc1bee22e409f96e93d7e117393172a'

    CFB EXAMPLE: (CFB128-AES192)
    ------------
    NIST Special Publication 800-38A http://cryptome.org/bcm/sp800-38a.htm#F

    >>> key = '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'.decode('hex')
    >>> IV = '000102030405060708090a0b0c0d0e0f'.decode('hex')
    >>> plain = '6bc1bee22e409f96e93d7e117393172a'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_CFB,IV=IV,segment_size=128)
    >>> output1 = cipher.encrypt(plain)
    >>> output1.encode('hex')
    'cdc80d6fddf18cab34c25909c99a4174'
    >>> plain = 'ae2d8a571e03ac9c9eb76fac45af8e51'.decode('hex')
    >>> output2 = cipher.encrypt(plain)
    >>> output2.encode('hex')
    '67ce7f7f81173621961a2b70171d3d7a'
    >>> decipher = python_AES.new(key,python_AES.MODE_CFB,IV=IV,segment_size=128)
    >>> decipher.decrypt(output1+output2).encode('hex')
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'

    CFB EXAMPLE: same as previous but now as a streamcipher
    ------------
    >>> key = '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'.decode('hex')
    >>> IV = '000102030405060708090a0b0c0d0e0f'.decode('hex')
    >>> plain = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_CFB,IV=IV,segment_size=128)
    >>> output = ''
    >>> for i in plain: output += cipher.encrypt(i)
    >>> output.encode('hex')
    'cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a'

    OFB EXAMPLE: (OFB128-AES192)
    ------------
    NIST Special Publication 800-38A http://cryptome.org/bcm/sp800-38a.htm#F

    >>> key = '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'.decode('hex')
    >>> IV = '000102030405060708090a0b0c0d0e0f'.decode('hex')
    >>> plain = '6bc1bee22e409f96e93d7e117393172a'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_OFB,IV)
    >>> output1 = cipher.encrypt(plain)
    >>> output1.encode('hex')
    'cdc80d6fddf18cab34c25909c99a4174'
    >>> plain = 'ae2d8a571e03ac9c9eb76fac45af8e51'.decode('hex')
    >>> output2 = cipher.encrypt(plain)
    >>> output2.encode('hex')
    'fcc28b8d4c63837c09e81700c1100401'
    >>> decipher = python_AES.new(key,python_AES.MODE_OFB,IV)
    >>> decipher.decrypt(output1 + output2).encode('hex')
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'

    OFB EXAMPLE: same as previous but now as a streamcipher
    ------------
    >>> key = '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'.decode('hex')
    >>> IV = '000102030405060708090a0b0c0d0e0f'.decode('hex')
    >>> plain = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_OFB,IV)
    >>> output = ''
    >>> for i in plain: output += cipher.encrypt(i)
    >>> output.encode('hex')
    'cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c1100401'


    CTR EXAMPLE:
    ------------
    NIST Special Publication 800-38A http://cryptome.org/bcm/sp800-38a.htm#F

    >>> from CryptoPlus.Util.util import Counter
    >>> key = '2b7e151628aed2a6abf7158809cf4f3c'.decode('hex')
    >>> counter = Counter('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex'))
    >>> cipher = python_AES.new(key,python_AES.MODE_CTR,counter=counter)
    >>> plaintext1 = '6bc1bee22e409f96e93d7e117393172a'.decode('hex')
    >>> plaintext2 = 'ae2d8a571e03ac9c9eb76fac45af8e51'.decode('hex')
    >>> plaintext3 = '30c81c46a35ce411e5fbc1191a0a52ef'.decode('hex')
    >>> ciphertext = cipher.encrypt(plaintext1 + plaintext2 + plaintext3)
    >>> ciphertext.encode('hex')
    '874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab'
    >>> counter2 = Counter('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex'))
    >>> decipher = python_AES.new(key,python_AES.MODE_CTR,counter=counter2)
    >>> decipher.decrypt(ciphertext).encode('hex')
    '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef'

    XTS EXAMPLE:
    ------------
    XTS-AES-128 applied for a data unit of 512 bytes
    IEEE P1619/D16: http://grouper.ieee.org/groups/1619/email/pdf00086.pdf

    >>> key = ('27182818284590452353602874713526'.decode('hex'),'31415926535897932384626433832795'.decode('hex'))
    >>> plaintext = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> ciphertext = cipher.encrypt(plaintext)
    >>> ciphertext.encode('hex')
    '27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad02655ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f4341332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203ebb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18deb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568'
    >>> decipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> decipher.decrypt(ciphertext).encode('hex')
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'

    using data sequence number n

    >>> key = ('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'.decode('hex'),'22222222222222222222222222222222'.decode('hex'))
    >>> plain ='4444444444444444444444444444444444444444444444444444444444444444'.decode('hex')
    >>> n = '3333333333'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> ciphertext = cipher.encrypt(plain,n)
    >>> ciphertext.encode('hex')
    'af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89'
    >>> decipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> decipher.decrypt(ciphertext,n).encode('hex')
    '4444444444444444444444444444444444444444444444444444444444444444'

    >>> key = ('27182818284590452353602874713526'.decode('hex'),'31415926535897932384626433832795'.decode('hex'))
    >>> plain ='72efc1ebfe1ee25975a6eb3aa8589dda2b261f1c85bdab442a9e5b2dd1d7c3957a16fc08e526d4b1223f1b1232a11af274c3d70dac57f83e0983c498f1a6f1aecb021c3e70085a1e527f1ce41ee5911a82020161529cd82773762daf5459de94a0a82adae7e1703c808543c29ed6fb32d9e004327c1355180c995a07741493a09c21ba01a387882da4f62534b87bb15d60d197201c0fd3bf30c1500a3ecfecdd66d8721f90bcc4c17ee925c61b0a03727a9c0d5f5ca462fbfa0af1c2513a9d9d4b5345bd27a5f6e653f751693e6b6a2b8ead57d511e00e58c45b7b8d005af79288f5c7c22fd4f1bf7a898b03a5634c6a1ae3f9fae5de4f296a2896b23e7ed43ed14fa5a2803f4d28f0d3ffcf24757677aebdb47bb388378708948a8d4126ed1839e0da29a537a8c198b3c66ab00712dd261674bf45a73d67f76914f830ca014b65596f27e4cf62de66125a5566df9975155628b400fbfb3a29040ed50faffdbb18aece7c5c44693260aab386c0a37b11b114f1c415aebb653be468179428d43a4d8bc3ec38813eca30a13cf1bb18d524f1992d44d8b1a42ea30b22e6c95b199d8d182f8840b09d059585c31ad691fa0619ff038aca2c39a943421157361717c49d322028a74648113bd8c9d7ec77cf3c89c1ec8718ceff8516d96b34c3c614f10699c9abc4ed0411506223bea16af35c883accdbe1104eef0cfdb54e12fb230a'.decode('hex')
    >>> n = 'ff'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> cipher.encrypt(plain,n).encode('hex')
    '3260ae8dad1f4a32c5cafe3ab0eb95549d461a67ceb9e5aa2d3afb62dece0553193ba50c75be251e08d1d08f1088576c7efdfaaf3f459559571e12511753b07af073f35da06af0ce0bbf6b8f5ccc5cea500ec1b211bd51f63b606bf6528796ca12173ba39b8935ee44ccce646f90a45bf9ccc567f0ace13dc2d53ebeedc81f58b2e41179dddf0d5a5c42f5d8506c1a5d2f8f59f3ea873cbcd0eec19acbf325423bd3dcb8c2b1bf1d1eaed0eba7f0698e4314fbeb2f1566d1b9253008cbccf45a2b0d9c5c9c21474f4076e02be26050b99dee4fd68a4cf890e496e4fcae7b70f94ea5a9062da0daeba1993d2ccd1dd3c244b8428801495a58b216547e7e847c46d1d756377b6242d2e5fb83bf752b54e0df71e889f3a2bb0f4c10805bf3c590376e3c24e22ff57f7fa965577375325cea5d920db94b9c336b455f6e894c01866fe9fbb8c8d3f70a2957285f6dfb5dcd8cbf54782f8fe7766d4723819913ac773421e3a31095866bad22c86a6036b2518b2059b4229d18c8c2ccbdf906c6cc6e82464ee57bddb0bebcb1dc645325bfb3e665ef7251082c88ebb1cf203bd779fdd38675713c8daadd17e1cabee432b09787b6ddf3304e38b731b45df5df51b78fcfb3d32466028d0ba36555e7e11ab0ee0666061d1645d962444bc47a38188930a84b4d561395c73c087021927ca638b7afc8a8679ccb84c26555440ec7f10445cd'

    >>> key = ('2718281828459045235360287471352662497757247093699959574966967627'.decode('hex'),'3141592653589793238462643383279502884197169399375105820974944592'.decode('hex'))
    >>> plain ='000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex')
    >>> n = 'ffffffffff'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> ciphertext = cipher.encrypt(plain,n)
    >>> ciphertext.encode('hex')
    '64497e5a831e4a932c09be3e5393376daa599548b816031d224bbf50a818ed2350eae7e96087c8a0db51ad290bd00c1ac1620857635bf246c176ab463be30b808da548081ac847b158e1264be25bb0910bbc92647108089415d45fab1b3d2604e8a8eff1ae4020cfa39936b66827b23f371b92200be90251e6d73c5f86de5fd4a950781933d79a28272b782a2ec313efdfcc0628f43d744c2dc2ff3dcb66999b50c7ca895b0c64791eeaa5f29499fb1c026f84ce5b5c72ba1083cddb5ce45434631665c333b60b11593fb253c5179a2c8db813782a004856a1653011e93fb6d876c18366dd8683f53412c0c180f9c848592d593f8609ca736317d356e13e2bff3a9f59cd9aeb19cd482593d8c46128bb32423b37a9adfb482b99453fbe25a41bf6feb4aa0bef5ed24bf73c762978025482c13115e4015aac992e5613a3b5c2f685b84795cb6e9b2656d8c88157e52c42f978d8634c43d06fea928f2822e465aa6576e9bf419384506cc3ce3c54ac1a6f67dc66f3b30191e698380bc999b05abce19dc0c6dcc2dd001ec535ba18deb2df1a101023108318c75dc98611a09dc48a0acdec676fabdf222f07e026f059b672b56e5cbc8e1d21bbd867dd927212054681d70ea737134cdfce93b6f82ae22423274e58a0821cc5502e2d0ab4585e94de6975be5e0b4efce51cd3e70c25a1fbbbd609d273ad5b0d59631c531f6a0a57b9'
    >>> decipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> decipher.decrypt(ciphertext,n).encode('hex')
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'

    using plaintext not a multiple of 16

    >>> key = ('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'.decode('hex'),'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0'.decode('hex'))
    >>> plaintext = '000102030405060708090a0b0c0d0e0f10111213'.decode('hex')
    >>> n = '9a78563412'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> ciphertext = cipher.encrypt(plaintext,n)
    >>> ciphertext.encode('hex')
    '9d84c813f719aa2c7be3f66171c7c5c2edbf9dac'
    >>> decipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> decipher.decrypt(ciphertext,n).encode('hex')
    '000102030405060708090a0b0c0d0e0f10111213'

    >>> key = ('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'.decode('hex'),'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0'.decode('hex'))
    >>> plaintext = '000102030405060708090a0b0c0d0e0f10'.decode('hex')
    >>> n = '9a78563412'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> ciphertext = cipher.encrypt(plaintext,n)
    >>> ciphertext.encode('hex')
    '6c1625db4671522d3d7599601de7ca09ed'
    >>> decipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> decipher.decrypt(ciphertext,n).encode('hex')
    '000102030405060708090a0b0c0d0e0f10'

    >>> key = ('e0e1e2e3e4e5e6e7e8e9eaebecedeeef'.decode('hex'),'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'.decode('hex'))
    >>> plaintext = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex')
    >>> n = '21436587a9'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> ciphertext = cipher.encrypt(plaintext,n)
    >>> ciphertext.encode('hex')
    '38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be68b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42ccbd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad38549c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a17741990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee39936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d48b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b883342729e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf92cefc151b5cc1611a167893819b63fb8a6b18e86de60290fa72b797b0ce59f3'
    >>> decipher = python_AES.new(key,python_AES.MODE_XTS)
    >>> decipher.decrypt(ciphertext,n).encode('hex')
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'

    CMAC EXAMPLE:
    -------------
    NIST publication 800-38B: http://csrc.nist.gov/publications/nistpubs/800-38B/Updated_CMAC_Examples.pdf

    >>> key = '2b7e151628aed2a6abf7158809cf4f3c'.decode('hex')
    >>> plaintext = '6bc1bee22e409f96e93d7e117393172a'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_CMAC)
    >>> cipher.encrypt(plaintext).encode('hex')[:16]
    '070a16b46b4d4144'

    CMAC EXAMPLE2:
    --------------
    >>> key = '2b7e151628aed2a6abf7158809cf4f3c'.decode('hex')
    >>> plaintext = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411'.decode('hex')
    >>> cipher = python_AES.new(key,python_AES.MODE_CMAC)
    >>> cipher.encrypt(plaintext).encode('hex')[:16]
    'dfa66747de9ae630'
    """
    return python_AES(key,mode,IV,counter,segment_size)

class python_AES(BlockCipher):
    key_error_message = ("Key should be 128, 192 or 256 bits")

    def __init__(self,key,mode,IV,counter,segment_size):
        cipher_module = rijndael
        args = {'block_size':16}
        self.blocksize = 16
        BlockCipher.__init__(self,key,mode,IV,counter,cipher_module,segment_size,args)

    def keylen_valid(self,key):
        return len(key) in (16,24,32)

# ---

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
  new_aes_xts = lambda aes_xts_key: AES_new((aes_xts_key[0 : 32], aes_xts_key[32 : 64]), MODE_XTS)
  cipher = new_aes_xts(aes_xts_key)
  if do_encrypt:
    return cipher.encrypt(data)
  else:
    return cipher.decrypt(data)


assert crypt_aes_xts('x' * 64, 'y' * 35, True).encode('hex') == '622de15539f9ebe251c97183c1618b2fa1289ef677ad71945095f99a59d7c366e69269'  # !! Move to test().

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


try:
  import Crypto.Util.strxor
  def make_strxor(size, strxor=Crypto.Util.strxor.strxor):
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
  sha512 = sys.modules('hashlib').sha512
else:
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
    raise ValueError('Missing NUL padding at 132.')
  if dechd[256 + 64 : 512].lstrip('\0'):
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


def test():
  passphrase = 'foo'
  raw_device = '7:0'
  decrypted_size = 0x9000
  sector_size = 512
  # Any 64 random bytes will do as a salt.
  salt = 'd97538ba99ca3182fd9e46184801a836a83a245f703247987dbd8d5c6a39ff5fbc4d03942ec54401d109d407c8033ede03930c95ddcc61b5b44ce3de6cac8b44'.decode('hex')
  # Any 64 random bytes will do as a keytable.
  keytable = 'a64cd0845765a19b0b5948f371f0b8c7b14da01677a10009d8b9199d511624233a54e1118dd6c9e2992e3ebae56081ca1f996c74c53f61f1a48f7fb17ddc6d5b'.decode('hex')
  enchd = salt + '55ade210c4de6bbf5f623fb944908f0b4952958188dbe9ff0723cc6d6e1fdbf9554f4c9a0bbb4f49066641911ccbcb212234a9e677de9404d58950f5eceab3b9d2b290c071e4c74ee848af4ec2d730b13ded8d9bce64b92786b6eaa1c5abe23f23601a2f4ce30283c791f571548ef30b3b32c4558ec102a96176eea3864e3c3bd0f853e55df2de9125c4e782aca78479065839d7878122d9dc5ac8af8626218a3f74ca327a79b61d0cee6f8c4c5972bd53a87fdb7732a86f775e7f6c7ac801b79fa75759554dce512daa6bc4444b49907fa8adb7e5f14963aa8a6a8a3a5bf51b549a7d7569d641331749e88f453163a56a7a3c7f46375b3adfba9f30be9c41200dd9779eaf52220e732f3e4c7ee9c501e63ccd9c6f53bbb70f649c08d64eb740e034e26cdf8dd8209b2e8da9aac90dab3005215410c48109f263e50ba1fa736fd2de0b252bc008f2f1eab2e0fb42c5579bab32ac86686cc264181790c3426eb16dcbdea12f708758e19bbae1072ef7157cef87fd8722f2d2eca8a85510b83ea3d534031e38e018f8554944681885f7d912760d449bca4fbc39ff9bd2c2192f71550b131b2a2afe6371c7c122e6f5c865cb2cbbf889d2ce54da9f55a2000cf4e0'.decode('hex')
  dechd = salt + ('564552410005010b5741849c0000000000000000000000000000000000000000000000000000000000009000000000000002000000000000000090000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b2df12c0' + keytable.encode('hex') + '00' * 192).decode('hex')
  header_key = '9e02d6ca37ac50a97093b3323545ec1cd9d11e03bfdaf123043bf1c42df5b6fc6660a2313e087fa80775942db79a9f297670f01ea6d555baa8599028cd8c8094'.decode('hex')

  assert len(salt) == 64
  assert len(enchd) == 512
  assert len(dechd) == 512
  assert dechd.startswith(salt)
  assert enchd.startswith(salt)
  assert dechd[256 : 256 + 64] == keytable

  check_full_dechd(dechd)
  assert build_dechd(salt, keytable, decrypted_size, sector_size) == dechd
  assert parse_dechd(dechd) == (keytable, decrypted_size)
  table = build_table(keytable, decrypted_size, raw_device)
  expected_table = '0 72 crypt aes-xts-plain64 a64cd0845765a19b0b5948f371f0b8c7b14da01677a10009d8b9199d511624233a54e1118dd6c9e2992e3ebae56081ca1f996c74c53f61f1a48f7fb17ddc6d5b 256 7:0 256 1 allow_discards\n'
  assert table == expected_table
  assert encrypt_header(dechd, header_key) == enchd
  assert decrypt_header(enchd, header_key) == dechd
  print >>sys.stderr, 'info: test continuing 1.'
  assert build_header_key(passphrase, salt) == header_key  # Takes about 6..60 seconds.
  print >>sys.stderr, 'info: test OK.'


def main(argv):
  raw_device = '7:0'

  #device = 'pp.bin'
  passphrase = 'ThisIsMyVeryLongPassphraseForMyVeraCryptVolume'

  #device = '../pts-static-cryptsetup/rr.bin'

  sys.stdout.write(get_table(device, passphrase, raw_device))
  sys.stdout.flush()


if __name__ == '__main__':
  test()
  #sys.exit(main(sys.argv))
