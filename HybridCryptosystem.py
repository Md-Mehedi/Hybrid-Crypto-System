######################################################################
##----------------------------- Imports ----------------------------##
##------------------------------------------------------------------##

from typing import List

from BitVector import *

from AES import AES
from Prime import Prime
from RSA import RSA

##------------------------------------------------------------------##
##----------------------------- Imports ----------------------------##
######################################################################




######################################################################
##------------------------- Helper Functions -----------------------##
##------------------------------------------------------------------##


##------------------------------------------------------------------##
##------------------------- Helper Functions -----------------------##
######################################################################




######################################################################
##------------------------- Class Definition -----------------------##
##------------------------------------------------------------------##

class Hybrid_Crypto_System:
  aes:AES
  rsa:RSA = RSA(16)

  def encrypt(self, plain_text:str) -> str:
    KEY = "Two One Nine One"
    self.aes = AES(KEY)
    cipher_text = self.aes.encrypt(plain_text)

    self.rsa = RSA(RSA_KEY_BIT)
    encrypted_key = self.rsa.encrypt(KEY)
    return [cipher_text, encrypted_key]
  
  def get_private_key(self):
    return self.rsa.get_private_key()

  def decrypt(self, encrypted_text:str, encrypted_key:str, private_key:List):
    self.rsa = RSA(RSA_KEY_BIT)
    self.rsa.set_private_key(private_key[0], private_key[1])
    plain_key = self.rsa.decrypt(encrypted_key)
    self.aes = AES(plain_key)
    return self.aes.decrypt(encrypted_text)

##------------------------------------------------------------------##
##------------------------- Class Definition -----------------------##
######################################################################




######################################################################
##--------------------------- Testing Code -------------------------##
##------------------------------------------------------------------##

TESTING = True
DEBUG = False

if TESTING :
  RSA_KEY_BIT = 128
  PLAIN_TEXT = "Hello!!! Now text can be Encrypt and Decrypt by Hybrid Crypto System class"
  hcs = Hybrid_Crypto_System()

  print("Plain text     : " + PLAIN_TEXT)

  encrypted_text = hcs.encrypt(PLAIN_TEXT)
  print("Encrypted text : " + encrypted_text[0])
  print("Encrypted key  : " + encrypted_text[1])

  private_key = hcs.get_private_key()
  print("Private key    : ", private_key)

  decrypted_text = hcs.decrypt(encrypted_text[0], encrypted_text[1], private_key)
  print("Decrypted text : " + decrypted_text)

##------------------------------------------------------------------##
##--------------------------- Testing Code -------------------------##
######################################################################
