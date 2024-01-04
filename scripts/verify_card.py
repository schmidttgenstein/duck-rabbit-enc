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
if __name__ == "__main__":
    uid = 109173807
    path_prefix = os.path.join("cards","c_"+str(uid))
    key_path =  os.path.join(path_prefix,"keys_"+str(uid)+".bin")
    enc_key = open(key_path,'rb').read()
    own_key = rsa.import_key(enc_key,passphrase = str(getpass.getpass('keyfile password: ')))
    for file_name in os.listdir(path_prefix):
        if 'check'in file_name:
            f_path = os.path.join(path_prefix,file_name)
            import_text = eval(decrypt_ciphertext(None,own_key,f_path))
            cards = import_text["cards"]
            hv = import_text["signed_hash"]
            pt_card = eval(cards)["plain"]
            hash_card = eval(cards)["hashed"]
            public_key = pt_card["public_key"]
            pk_rsa = rsa.import_key(public_key)
            assert verify_entry(cards,hv,pk_rsa), "hash not verified, data may have been altered!"
            verified_card_plain = {"verifier_key":own_key.public_key().export_key(),"public_key":public_key}
            verified_card_hash =  {"verifier_key":own_key.public_key().export_key(),"public_key":public_key}
            for k,pv in pt_card.items():
                hv = hash_card[k]
                if verify_entry(pv,hv,pk_rsa):
                    verified_card_plain[k] = dencode(pv,own_key.d,own_key.n)
                    verified_card_hash[k] = dencode(hv,own_key.d,own_key.n)
            v_cards = {"plain":verified_card_plain,"hashed":verified_card_hash}
            v_hash = dencode(cards,own_key.d,own_key.n)
            v_path = os.path.join(path_prefix,file_name[:-10]+"_verified.txt")
            enc_card = encrypt_plaintext(str({"cards":v_cards,"signed_hash":v_hash}),pk_rsa,v_path)

