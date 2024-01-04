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
    entity_mapping = {"person":"p","government":"g","corporation":"c"}
    keys = rsa.generate(bits = 2048)
    pkey = keys.public_key().export_key()
    card = {"public_key":pkey} 
    uid = random.randint(1,int(10**10))
    card["uid"] = uid 
    path_prefix = "./cards/"
   
    entity = input("entity (person, government, corporation): ")

    enc_key = keys.export_key(passphrase = str(getpass.getpass("create a key password: ")),pkcs = 8)
    card["entity"] = entity
    card_dir = os.path.join(path_prefix,entity_mapping[entity] +"_"+str(uid))
    os.mkdir(path_prefix+entity_mapping[entity] +"_"+str(uid))
    key_path = os.path.join(card_dir,"keys_"+str(uid)+".bin")
    fout = open(key_path,"wb")
    fout.write(enc_key)
    fout.close()
    enc_key = open(key_path,"rb").read()
    try: 
        key = rsa.import_key(enc_key,passphrase = str(getpass.getpass("verify password: ")))
        cont = True 
        print("hit enter w/o providing input to escape")
        while cont: 
            card_key = input("entry header: ")
            if len(card_key) == 0:
                break
            card_value = input("entry value: ")        
            if len(card_value) == 0:
                break
            card[card_key] = card_value 
        file_name_plain = os.path.join(card_dir,str(uid)+"_plain.txt")
        file_name_public = os.path.join(card_dir,str(uid)+"_address.yaml")

        enc_card = encrypt_plaintext(str(card),keys.public_key(),file_name_plain)
        assert eval(decrypt_ciphertext(enc_card,keys)) == card, "encryption/decryption not functioning properly"
        address_card = {"uid":uid,"public_key":keys.public_key().export_key(),"entity":entity}
        with open(file_name_public,mode = "wt", encoding="utf8") as f:
            yaml.dump(address_card,f)
    except:
        print("passwords do not match!")

    


