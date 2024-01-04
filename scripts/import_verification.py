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
    uid = 5813200253
    tid = 109173807
    path_pref = os.path.join("./cards","p_"+str(uid))
    key_path = os.path.join(path_pref,"keys_"+str(uid)+".bin")
    enc_keys = open(key_path,"rb").read()
    keys = rsa.import_key(enc_keys,passphrase = str(getpass.getpass("key password: ")))
    for file_name in os.listdir(path_pref):
        if 'verified' in file_name:
            c_path = os.path.join(path_pref,str(uid)+"_plain.txt")
            own_card = eval(decrypt_ciphertext(None,keys,c_path))
            vid = file_name[:-13]
            v_path = os.path.join(path_pref,file_name)
            v_address = os.path.join("cards","c_"+str(vid),str(vid)+"_address.yaml")
            with open(v_address,mode="rt",encoding="utf-8") as f:
                verifier_address = yaml.safe_load(f)
            v_key = rsa.import_key(verifier_address["public_key"])
            verified_text = eval(decrypt_ciphertext(None,keys,v_path))
            v_card = verified_text["verified_card"]
            v_hash = verified_text["signed_hash"]
            assert verify_entry(str(v_card),v_hash,v_key), "wrong key information used!"
            verified_card = {"vid":v_card["vid"],"v_key":v_card["verifier_key"],"card_verified":str(v_card),"card_hash":v_hash}
            if "verified_cards" in own_card.keys():
                own_card["verified_cards"][v_card["vid"]] = verified_card
            else:
                own_card["verified_cards"] = {v_card["vid"]: verified_card}

    enc_card = encrypt_plaintext(str(verified_card),keys.public_key(),c_path)


