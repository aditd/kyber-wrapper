from ctypes import cdll, cast, create_string_buffer
from ctypes import c_int, c_ubyte, POINTER, c_uint8, c_size_t
import ctypes as ct  
# OQS_SIG_keypair(uint8_t *public_key, uint8_t *secret_key) 
kyber512_SECRETKEYBYTES = 1632
kyber512_PUBLICKEYBYTES = 800
kyber512_CIPHERTEXTBYTES = 768
kyber512_SHAREDSECRETBYTES = 32
#define pqcrystals_kyber512_SECRETKEYBYTES 1632
#define pqcrystals_kyber512_PUBLICKEYBYTES 800
#define pqcrystals_kyber512_CIPHERTEXTBYTES 768
#define pqcrystals_kyber512_BYTES 32


import pathlib

import os, sys

if os.name == "posix" and sys.platform == "darwin":
    libname = pathlib.Path().absolute() / "ref/libpqcrystals_kyber512_ref.dylib"
    libdil = cdll.LoadLibrary(libname)
else:
    libdil = cdll.LoadLibrary('ref/libpqcrystals_kyber512_ref.so')


kyb_keypair = libdil.pqcrystals_kyber512_ref_keypair
kyb_encrypt = libdil.pqcrystals_kyber512_ref_enc
kyb_decrypt = libdil.pqcrystals_kyber512_ref_dec



class Kyber():
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
    def __init__(self, name = "Test", file="", is_kem=True):
        self.name = name
        if file=="":
            rv = self.keygen()
        else:
            self.public_key = 
            self.public_key = 2

    def keygen(self):
        self.public_key = create_string_buffer(kyber512_PUBLICKEYBYTES)
        self.secret_key = create_string_buffer(kyber512_SECRETKEYBYTES)
        kyb_keypair(ct.byref(self.public_key), ct.byref(self.secret_key))
        return bytes(self.public_key), bytes(self.secret_key)
           
    def encap(self, shared_key = None):
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
        ciphertext = ct.create_string_buffer(kyber512_CIPHERTEXTBYTES)
        shared_secret = ct.create_string_buffer(kyber512_SHAREDSECRETBYTES)
        rv = kyb_encrypt(ct.byref(ciphertext), ct.byref(shared_secret), self.public_key)
        return bytes(ciphertext), bytes(shared_secret)

    def decap(self, ciphertext):
        """
        Returns the shared secret decrypted from the ciphertext

        Parameters
        ----------
        ciphertext: bytes
        """
        my_ciphertext = ct.create_string_buffer(ciphertext, kyber512_CIPHERTEXTBYTES)
        shared_secret = ct.create_string_buffer(kyber512_SHAREDSECRETBYTES)
        rv = kyb_decrypt(ct.byref(shared_secret), my_ciphertext, self.secret_key)
        return bytes(shared_secret)
    

    def __repr__(self):
        return str(self.details)
    
