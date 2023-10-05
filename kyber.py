from ctypes import cdll, cast, create_string_buffer
from ctypes import c_int, c_ubyte, POINTER, c_uint8, c_size_t
import ctypes as ct  

import pathlib

import os, sys

if os.name == "posix" and sys.platform == "darwin":
    libname = pathlib.Path().absolute() / "ref/libpqcrystals_kyber512_ref.dylib"
    libdil = cdll.LoadLibrary(libname)
else:
    libdil = cdll.LoadLibrary('ref/libpqcrystals_kyber512_ref.so')


kyb_keypair = libdil.pqcrystals_kyber512_ref_keypair
kyb_encap = libdil.pqcrystals_kyber512_ref_enc
kyb_decrypt = libdil.pqcrystals_kyber512_ref_dec
kyb_encrypt = libdil.pqcrystals_kyber512_ref_encrypt

class Kyber512():
    """
    Attributes
    ----------
    name : str
        name of the entity using the algorithm
    entity : oqs.KeyEncapsulation | None
        KeyEncapsulation object instance in case of KEM otherwise None
    public_key : bytes
        Kyber public key
    details : dict | None
        details including the key sizes, version of the algorithm 
        None in case of non-KEM
    kem_variant : string
        the version of the kyber algorithm
    secret_key : bytes
        the secret key in byte
    is_kem : bool
        whether to use the KEM algorithm or not
    
    Methods
    -------
    keygen(self, secret_key = None, public_key = None):
        Generates the secret key and the public key
        Optionally, the secret key and the public key can be provided
    encap(self, public_key):
        Returns the ciphertext and the shared secret
    decap(self, ciphertext):
        Returns the shared secret decrypted from the ciphertext
    """
    length_secret_key = 1632
    length_public_key = 800
    length_ciphertext =  768
    length_shared_secret = 32

    def __init__(self, name = "Test", secret_key=False, public_key=False):
        self.name = name
        if secret_key:
            self.secret_key = ct.create_string_buffer(secret_key, self.length_secret_key)
        if public_key:
            self.public_key = ct.create_string_buffer(public_key, self.length_public_key)
        

    def keygen(self):
        self.public_key = create_string_buffer(self.length_public_key)
        self.secret_key = create_string_buffer(self.length_secret_key)
        kyb_keypair(ct.byref(self.public_key), ct.byref(self.secret_key))
        return bytes(self.public_key), bytes(self.secret_key)
           
    def encap(self, shared_secret = None):
        """
        Returns the ciphertext and the shared secret

        Returns
        -------
        ciphertext: bytes
            Encrypted shared secret
            The size of the ciphertext depends on the algorithm. access self.details to learn about the size
        shared_secret: bytes
            the shared secret. size is 32 bytes when using Kyber512
        """
        # my_public_key = ct.create_string_buffer(self.public_key, kyber512_PUBLICKEYBYTES)
        ciphertext = ct.create_string_buffer(self.length_ciphertext)
        if shared_secret:
            shared_secret = ct.create_string_buffer(shared_secret, self.length_shared_secret)
            rv = kyb_encrypt(ct.byref(ciphertext), ct.byref(shared_secret), self.public_key)
        else:
            shared_secret = ct.create_string_buffer(self.length_shared_secret)
            rv = kyb_encap(ct.byref(ciphertext), ct.byref(shared_secret), self.public_key)
        return bytes(ciphertext), bytes(shared_secret)

    def decap(self, ciphertext):
        """
        Returns the shared secret decrypted from the ciphertext

        Parameters
        ----------
        ciphertext: bytes
        """
        my_ciphertext = ct.create_string_buffer(ciphertext, self.length_ciphertext)
        shared_secret = ct.create_string_buffer(self.length_shared_secret)
        rv = kyb_decrypt(ct.byref(shared_secret), my_ciphertext, self.secret_key)
        return bytes(shared_secret)
    

    def __repr__(self):
        return str(self.details)
    
# import secrets

# random_bytes = secrets.token_bytes(32)

# # print("random:", random_bytes)
# x = Kyber512()
# x.keygen()
# cipher, ss = x.encap()

# print("shared secret:", ss)

# decrypted = x.decap(cipher)
# print("decrypted:",decrypted)