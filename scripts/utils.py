import os 
import yaml 
import getpass
import random 
import base64
from hashlib import sha512 as sha 
from Crypto.PublicKey import RSA as rsa 
from Crypto.Cipher import AES as aes, PKCS1_OAEP as pkcs 
from Crypto.Random import get_random_bytes 
    
def dencode(val,key,n):
    if type(val) is not bytes:
        if type(val) is int:
            val = str(val)
        val = val.encode("utf8")
    return pow(int.from_bytes(sha(val).digest(),byteorder="big"),key,n)

def intdehash(val):
    if type(val) is not bytes:
        if type(val) is int:
            val = str(val)
        val = val.encode("utf8")
    return int.from_bytes(sha(val).digest(),byteorder="big")

def encrypt_plaintext(text,recipient_key,f_name = None):
    if type(text) is not bytes:
        text = text.encode("utf8")
    session_key = get_random_bytes(16)
    cipher_rsa = pkcs.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = aes.new(session_key,aes.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(text)
    if f_name is not None:
        f_out = open(f_name,"wb")
        [f_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
        f_out.close()
    cipher = (enc_session_key, cipher_aes.nonce, tag, ciphertext)
    return cipher


def decrypt_ciphertext(cipher_in,own_key,f_name = None):
    cipher_rsa = pkcs.new(own_key)
    if f_name is not None:
        f_in = open(f_name,"rb")
        cipher_in = [f_in.read(x) for x in (own_key.size_in_bytes(), 16,16,-1)]
    enc_cipher_key = cipher_in[0]
    nonce = cipher_in[1]
    tag = cipher_in[2]
    ciphertext = cipher_in[3]
    session_key =  cipher_rsa.decrypt(enc_cipher_key)
    cipher_aes = aes.new(session_key,aes.MODE_EAX,nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext,tag).decode("utf8")
    return plaintext 


def verify_entry(plain_value,hashed_value,public_key):
    pv_int = intdehash(plain_value)
    hv_int = pow(hashed_value,public_key.e,public_key.n)
    return True if  pv_int == hv_int else False 