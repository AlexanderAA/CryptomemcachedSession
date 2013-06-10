"""
Copyright (c) 2013 
   Aliaksandr Abushkevich <alex@abushkevi.ch>. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software
   must display the following acknowledgement:
     This product includes software developed by Aliaksandr Abushkevich.
4. Neither the name of the University nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR 
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, 
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF 
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""

import base64
import binascii
import cherrypy
import hashlib
import hmac
import logging
import os
import pickle
from Crypto.Cipher import Blowfish
from StringIO import StringIO


log = logging.getLogger('CryptomemcachedSession')


class CryptoPickler(pickle.Pickler):
    """ Provides familiar pickle.Pickler interface with dump() method,
    handles decryption transparently in the background.
    
    Inherited from object, because there should only two methods available:
    __init__() and dump()
    """
    def __init__(self, file, protocol=None):
        self.write = file.write
        self.protocol = protocol

    def dump(self, obj):
        plaintext_file = StringIO()
        pickle.Pickler(plaintext_file, self.protocol).dump(obj)
        plaintext = plaintext_file.getvalue()
        
        ciphertext = self._encrypt(plaintext)
        self.write(ciphertext)
    
    @staticmethod
    def _pad(string):
        block_size = 8
        encoded_string = base64.b64encode(string)
        modulo = len(encoded_string) % block_size
        if modulo == 0:
            result = encoded_string
            return result
        pad_len = block_size - modulo
        padding = 'X' * pad_len # replace to something random
        result = '{0}{1}'.format(encoded_string, padding)
        return result
    
    def _encrypt(self, plaintext):
        IV = os.urandom(8)
        if len(self.KEY) > 56:
            log.error('Session key is longer than 56 symbols.')
            raise ValueError('Session key is longer than 56 symbols.')
        bc = Blowfish.new(key = self.KEY, mode = Blowfish.MODE_CBC, IV = IV)
        plaintext_padded = self._pad(plaintext)
        ciphertext = IV + bc.encrypt(plaintext_padded)
        return ciphertext

class CryptoUnpickler(object):
    """ Provides familiar pickle.Unpickler interface with load() method,
    handles decryption transparently in the background.
    
    Inherited from object, because there should only two methods available:
    __init__() and load()
    """
    KEY = None
    def __init__(self, file):
        ciphertext = file.read()
        plaintext = self._decrypt(ciphertext)
        plaintext_file = StringIO()
        plaintext_file.write(plaintext)
        plaintext_file.seek(0)
        self.plaintext_file = plaintext_file
    
    def load(self):
        return pickle.Unpickler(self.plaintext_file).load()
    
    @staticmethod
    def _unpad(string):
        return base64.b64decode(string)
        
    def _decrypt(self, ciphertext):
        IV = '00001111'
        bc = Blowfish.new(key = self.KEY, mode = Blowfish.MODE_CBC, IV = IV)
        plaintext_padded = bc.decrypt(ciphertext)[8:]
        plaintext = self._unpad(plaintext_padded)
        return plaintext

def CryptoUnpicklerFactory(key):
    cu = CryptoUnpickler
    cu.KEY = key
    return cu

def CryptoPicklerFactory(key):
    cp = CryptoPickler
    cp.KEY = key
    return cp

class CryptomemcachedSession(cherrypy.lib.sessions.MemcachedSession):
    """ Provides (hopefully) secure session backend. 
    Redefines 3 methods of the parent class and adds another 3 methods.
    
    * Authenticity
        Session IDs are signed using sha256 HMAC.
    
    * Scaling
        2(?) requests to memcached per request
    
    * Session data encryption
        Session data is encrypted transparently (Blowfish CBC)
    
    Add the following to your cherrypy config to enable CryptomemcachedSession:
    # Add custom session backend
    session.CryptomemcachedSession.TOKEN_SIZE = config['session']['token_size']
    session.CryptomemcachedSession.KEY = config['session']['key']
    cherrypy.lib.sessions.CryptomemcachedSession =session.CryptomemcachedSession
    """
    
    TOKEN_SIZE = None
    KEY = None
    SIGNATURE_LENGTH = None

    def __init__(self, id=None, **kwargs):
        """
        """
        self.SIGNATURE_LENGTH = len(
            self._sign('length check key', 'length check value')
        )
        
        self.id_observers = []
        self._data = {}
        
        for k, v in kwargs.iteritems():
            setattr(self, k, v)
        
        if id is None:
            self.regenerate()
        else:
            if not self._signature_ok(id):
                log.error('Session ID signature is incorrect.'
                          ' Possible break-in attempt!')
                self.id = None
                self.regenerate()
            else:
                self.id = id
                if not self._exists():
                    # Expired or malicious session. Make a new one.
                    # See http://www.cherrypy.org/ticket/709.
                    self.id = None
                    self.regenerate()
    
    @classmethod
    def setup(cls, **kwargs):
        """Set up the storage system for memcached-based sessions.
        
        This should only be called once per process; this will be done
        automatically when using sessions.init (as the built-in Tool does).
        """
        for k, v in kwargs.iteritems():
            setattr(cls, k, v)
        
        import memcache
        cls.cache = memcache.Client(
            cls.servers, 
            pickler=CryptoPicklerFactory(key = cls.KEY), 
            unpickler=CryptoUnpicklerFactory(key = cls.KEY),
        )
    
    #--- Session ID ------------------------------------------------------------
    def generate_id(self):
        """Return a new session id.
        
        Note: memcacached will not accept keys longer than 250 bytes.
        """
        token = self._create_unique_token(self.TOKEN_SIZE)
        signature = self._sign(self.KEY, token)
        signed_id = '{0}{1}'.format(token, signature)
        return signed_id
        
    @staticmethod
    def _sign(key, value):
        hmac_hash_hex = hmac.new(key, value, hashlib.sha256).hexdigest()
        return hmac_hash_hex
    
    @staticmethod
    def _create_unique_token(token_size):
        """ Result is longer than token_size
        """
        random_bytes_hex = binascii.hexlify(os.urandom(token_size))
        return random_bytes_hex
    
    def _signature_ok(self, session_id):
        token     = session_id[:-self.SIGNATURE_LENGTH]
        signature = session_id[-self.SIGNATURE_LENGTH:]
        result = (self._sign(self.KEY, token) == signature)
        return result
    
    #--- END Session ID --------------------------------------------------------
