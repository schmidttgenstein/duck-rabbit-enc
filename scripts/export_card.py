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
    #TODO: eliminate enttiy prefix in directory / handle self & target ids better, rn hardcoded 
    uid = 5813200253
    tid = 109173807
    path_pref = os.path.join("./cards","p_"+str(uid))
    key_path = os.path.join(path_pref,"keys_"+str(uid)+".bin")
    ucard_path = os.path.join(path_pref,str(uid)+"_plain.txt")
    targ_pref = os.path.join("./cards","c_"+str(tid))
    targ_path = os.path.join(targ_pref,str(tid)+"_address.yaml")
    with open(targ_path,mode="rt",encoding="utf-8") as f:
        tcard  = yaml.safe_load(f)
    enc_keys = open(key_path,"rb").read()
    keys = rsa.import_key(enc_keys,passphrase = str(getpass.getpass("key password: ")))
    plain_card = eval(decrypt_ciphertext(None,keys,ucard_path))
    target_card_plain = {}
    target_card_hashed = {}
    tkey = rsa.import_key(tcard["public_key"])
    public_key = plain_card.get("public_key")
    try:
        target_card_plain["public_key"] = public_key
    except KeyError:
        print("error: card has no public_key")
    target_card_hashed["public_key"] = dencode(public_key,keys.d,keys.n)
    for k,v in plain_card.items():
        response = input(f"include entry for {k}?: y/n ")
        if response in ['y','yes','Y','Yes']:
            target_card_plain[k] = v 
            target_card_hashed[k] = dencode(v,keys.d,keys.n)
    
    target_path_ucard = os.path.join(targ_pref,str(uid)+"_check.txt")
    cards = str({"plain": target_card_plain, "hashed": target_card_hashed})
    cards_hash = dencode(cards,keys.d,keys.n)
    enc_card = encrypt_plaintext(str({"cards":cards,"signed_hash":cards_hash}),tkey,target_path_ucard)
