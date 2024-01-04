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
''' 
def encrypt_text(text,recipient_key):
    cipher = pkcs.new(recipient_key)
    cipher_message = cipher.encrypt(text)
    encoded_message = base64.b64encode(cipher_message)
    return encoded_message
'''


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
        cipher_in = [f_in.read(x) for x in (own_key.size_in_byes(), 16,16,-1)]
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
    os.mkdir(path_prefix+str(uid))
    card_dir = path_prefix+str(uid) +'/'
    enc_key = keys.export_key(passphrase = str(getpass.getpass("key password: ")),pkcs = 8)
    key_path = card_dir+"keys_"+str(uid)+".bin"
    fout = open(key_path,"wb")
    fout.write(enc_key)
    fout.close()
    enc_key = open(key_path,"rb").read()
    try: 
        key = rsa.import_key(enc_key,passphrase = str(getpass.getpass("verify password: ")))
    except:
        print("passwords do not match!")
    cont = True 
    entity = input("entity (person, government, corporation): ")
    print("hit enter w/o providing input to escape")
    card["entity"] = entity
    while cont: 
        card_key = input("entry header: ")
        if len(card_key) == 0:
            break
        card_value = input("entry value: ")        
        if len(card_value) == 0:
            break
        card[card_key] = card_value 
    file_name_plain = card_dir + entity_mapping[entity]+"_"+str(uid)+"_plain.txt"
    file_name_public = card_dir + entity_mapping[entity]+"_"+str(uid)+"_address.yaml"

    enc_card = encrypt_plaintext(str(card),keys.public_key(),file_name_plain)
    assert eval(decrypt_ciphertext(enc_card,keys)) == card, "encryption/decryption not functioning properly"
    address_card = {"uid":uid,"public_key":keys.public_key().export_key()}
    with open(file_name_public,mode = "wt", encoding="utf8") as f:
        yaml.dump(address_card,f)

    
    ''' file_name_hashed = card_dir + entity_mapping[entity]+"_"+str(uid)+"_hashed.yaml"

    with open(file_name_plain,mode = "wt",encoding="utf-8") as f:
        yaml.dump(card,f)
    hashed_card = {}
    for k, v in card.items():
        hashed_card[k] = hex(dencode(v,keys.d,keys.n))
    hashed_card = dict(sorted(hashed_card.items()))
    lock_hc = dencode(str(hashed_card),keys.d,keys.n)
    hashed_card["hash"] = hex(lock_hc)
    with open(file_name_hashed,mode = "wt", encoding="utf8") as f:
        yaml.dump(hashed_card,f)
    '''

