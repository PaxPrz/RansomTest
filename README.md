# RansomTest
This is a working model of a ransomware software. It encrypts all images located in the current directory using AES encryption.

## To run the software
-----------------------------

### Install python3
> apt install python3

> pip3 install -r requirements.txt

### Run encrypt.py
> python3 encrypt.py

### To get files back
- Copy the DecryptInfo.pass file to serverFiles folder
- Execute the serverdecrypt.py
> python3 serverdecrypt.py
- Move the victim_private.PEM file back to client directory
- Execute decrypt.py
> python3 decrypt.py
