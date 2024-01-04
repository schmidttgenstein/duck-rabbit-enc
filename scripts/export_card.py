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
    public_key = plain_card.pop("public_key")
    target_card_plain["public_key"] = public_key
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
