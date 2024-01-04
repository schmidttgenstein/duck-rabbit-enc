import os 
import yaml 
import getpass
import random 
from hashlib import sha512 as sha 
from Crypto.PublicKey import RSA as rsa 


    
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


if __name__ == "__main__":
    uid = 4600546284
    tid = 6468280872
    key_path = "./cards/"+str(uid)+"keys_"+str(uid)+".bin"
    path_pref = os.path.join("./cards",str(uid))
    key_path = os.path.join(path_pref,"keys_"+str(uid)+".bin")
    ucard_path = os.path.join(path_pref,"p_"+str(uid)+"_plain.yaml")
    hcard_path = os.path.join(path_pref,"p_"+str(uid)+"_hashed.yaml")
    tcard_path = os.path.join("./cards",str(tid),"c_"+str(tid)+"_plain.yaml")
    with open(ucard_path,mode="rt",encoding="utf-8") as f:
        ucard  = yaml.safe_load(f)
    with open(hcard_path,mode="rt",encoding="utf-8") as f:
        hcard  = yaml.safe_load(f)
    with open(tcard_path,mode="rt",encoding="utf-8") as f:
        tcard  = yaml.safe_load(f)
    enc_keys = open(key_path,"rb").read()
    keys = rsa.import_key(enc_keys,passphrase = str(getpass.getpass("key password: ")))
    tkey = rsa.import_key(tcard["public_key"])
    #for k,v in ecard.items():

    signed_hash = hcard.pop("hash")
    dehashed = intdehash(str(hcard))
    int_hash = pow(int(signed_hash,16),keys.e,keys.n)