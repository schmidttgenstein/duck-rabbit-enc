import os 
import yaml 
import getpass
import random 
import base64
from hashlib import sha512 as sha 
from Crypto.PublicKey import RSA as rsa 
from Crypto.Cipher import AES as aes, PKCS1_OAEP as pkcs 
from Crypto.Random import get_random_bytes 
from utils import *

    

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
            verified_card = {"verifier_key":own_key.public_key().export_key(),"vid":uid,"public_key":public_key}
            for k,pv in pt_card.items():
                hv = hash_card[k]
                if verify_entry(pv,hv,pk_rsa):
                    verified_card[k] = dencode(hv,own_key.d,own_key.n)
            v_hash = dencode(str(verified_card),own_key.d,own_key.n)
            path_prefix = os.path.join("cards","p_"+str(pt_card['uid']))
            #Notice that we save verified data in verified's directory with verifi*ers* id in file name
            v_path = os.path.join(path_prefix,str(uid)+"_verified.txt")
            enc_card = encrypt_plaintext(str({"verified_card":verified_card,"signed_hash":v_hash}),pk_rsa,v_path)

