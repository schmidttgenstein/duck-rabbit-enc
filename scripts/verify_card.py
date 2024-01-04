import yaml 
import getpass
import random 
from hashlib import sha512 as sha 
from Crypto.PublicKey import RSA as rsa 


    
def dencode(val,key,n):
    if type(val) is not bytes:
        val = val.encode("utf8")
    return pow(int.from_bytes(sha(val).digest(),byteorder="big"),key,n)

def intdehash(val):
    if type(val) is not bytes:
        val = val.encode("utf8")
    return int.from_bytes(sha(val).digest(),byteorder="big")

if __name__ == "__main__":
    key_path = "682880708.bin"
    enc_key = open(key_path,'rb').read()
    own_key = rsa.import_key(enc_key,passphrase = str(getpass.getpass('keyfile password: ')))
    card_path = 'p_8942467848.yaml'
    input_path = 'p_8942467848_plain.yaml'
    if card_path is None:
        uid = str(input("entity uid (e_uid): "))
        card_path = uid + ".yaml"
        input_path = uid + "_plain.yaml"
    with open(card_path,mode="rt",encoding="utf-8") as f:
        ecard_hash = yaml.safe_load(f)
    with open(input_path,mode="rt",encoding="utf-8") as f:
        ecard_plain = yaml.safe_load(f)
    prop_key = rsa.import_key(ecard_plain['public_key'])
    hashed_public_key = int(ecard_hash['signed_key'],16)
    decrypted_public_key =  pow(hashed_public_key,prop_key.e,prop_key.n)
    if intdehash(ecard_plain["public_key"]) != decrypted_public_key:
        raise "keys do not match!"
    
    for d_key in ecard_plain.keys():
        #hashed dictionary keys must include those in ecard
        if d_key in ecard_hash:
            plain_value = intdehash(ecard_plain[d_key]) #dencode(ecard_plain[d_key],prop_key.e,prop_key.n)
            try:
                hashed_int = int(ecard_hash[d_key],16)
                hashed_val = pow(hashed_int,prop_key.e,prop_key.n)
                if hashed_val == plain_value:
                    print(f"value for key {d_key} is a match!")
                else:
                    print('yikes')
            except:
                print(f'cannot ints {d_key}')
    ''' 
    keys = rsa.generate(bits = 2048)
    pkey = keys.public_key().export_key()
    card = {"public_key":pkey} 
    signed_key = pow(int.from_bytes(sha(pkey).digest(),byteorder='big'),keys.d,keys.n)
    card["signed_key"] = hex(signed_key)
    uid = random.randint(1,int(10**10))
    card["uid"] = uid 
    enc_key = keys.export_key(passphrase = str(getpass.getpass('key password: ')),pkcs = 8)
    fout = open('rsa_key.bin','wb')
    fout.write(enc_key)
    fout.close()
    enc_key = open('rsa_key.bin','rb').read()
    '''