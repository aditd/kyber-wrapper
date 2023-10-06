from ctypes import cdll, cast, create_string_buffer
from ctypes import c_int, c_ubyte, POINTER, c_uint8, c_size_t
import ctypes as ct  

import pathlib

import os, sys

if os.name == "posix" and sys.platform == "darwin":
    libname = "libpqcrystals_kyber512_ref.dylib"
    print(libname)
    libdil = cdll.LoadLibrary(libname)
else:
    libdil = cdll.LoadLibrary('libpqcrystals_kyber512_ref.so')


kyb_keypair = libdil.pqcrystals_kyber512_ref_keypair
kyb_encap = libdil.pqcrystals_kyber512_ref_enc
kyb_decap = libdil.pqcrystals_kyber512_ref_dec
kyb_encrypt = libdil.pqcrystals_kyber512_ref_encrypt
kyb_decrypt = libdil.pqcrystals_kyber512_ref_decrypt

class Kyber512():
    """
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

    def __init__(self):
        pass       

    def keygen(self):
        public_key = create_string_buffer(self.length_public_key)
        secret_key = create_string_buffer(self.length_secret_key)

        kyb_keypair(ct.byref(public_key), ct.byref(secret_key))

        return bytes(public_key), bytes(secret_key)
           
    def encap(self, public_key, shared_secret = None):
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

        public_key = ct.create_string_buffer(public_key, self.length_public_key)
        ciphertext = ct.create_string_buffer(self.length_ciphertext)
        ciphertexts = b""

        if shared_secret!=None:
            # chunk the shared key into {kyber_msg_space} bytes blocks
            for i in range(0, len(shared_secret), self.length_shared_secret):
                shared_secret_i = ct.create_string_buffer(shared_secret[i:i+self.length_shared_secret], self.length_shared_secret)
                _ = kyb_encrypt(ct.byref(ciphertext), ct.byref(shared_secret_i), public_key)
                ciphertexts += bytes(ciphertext)   # concatenate the ciphertexts

        else:
            shared_secret = ct.create_string_buffer(self.length_shared_secret)
            _ = kyb_encap(ct.byref(ciphertext), ct.byref(shared_secret), public_key)
            ciphertexts = ciphertext

        return bytes(ciphertexts), bytes(shared_secret)

    def decap(self, ciphertext, secret_key, is_kem=True):
        """
        Returns the shared secret decrypted from the ciphertext

        Parameters
        ----------
        ciphertext: bytes
        """

        plaintext = b""
        secret_key = ct.create_string_buffer(secret_key, self.length_secret_key)
        if is_kem:
            my_ciphertext = ct.create_string_buffer(ciphertext, self.length_ciphertext)
            shared_secret = ct.create_string_buffer(self.length_shared_secret)

            _ = kyb_decap(ct.byref(shared_secret), my_ciphertext, secret_key)
            plaintext = shared_secret

        else:
            # chunk the shared key into {kyber_msg_space} bytes blocks
            for i in range(0, len(ciphertext), self.length_ciphertext):
                block = ct.create_string_buffer(ciphertext[i:i+self.length_ciphertext], self.length_ciphertext)  
                shared_secret = ct.create_string_buffer(self.length_shared_secret)

                _ = kyb_decrypt(ct.byref(shared_secret), block, secret_key)
                plaintext += bytes(shared_secret)   # concatenate the plaintexts

        return bytes(plaintext)
    

    def __repr__(self):
        pass    
