######################################################################
##----------------------------- Imports ----------------------------##
##------------------------------------------------------------------##

from pathlib import Path
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
  aes:AES = None
  rsa:RSA = None
  KEY = None
  RSA_K = None

  def __init__(self, rsa_k, key="Something used as key") -> None:
    self.KEY = key
    self.RSA_K = rsa_k
    self.aes = AES(self.KEY)
    self.rsa = RSA(self.RSA_K)

  def encrypt(self, plain_text:str) -> str:
    """ Return encrypted text and encrypted key as pair """
    cipher_text = self.aes.encrypt(plain_text)
    encrypted_key = self.rsa.encrypt(self.KEY)
    return [cipher_text, encrypted_key]

  # def encrypt_file(self, file_text:str)->str:
  #   """ Return encrypted file as bytes and encrypted key as pair """
  #   cipher_text = self.aes.encrypt_file(file_text)
  #   encrypted_key = self.rsa.encrypt(self.KEY)
  #   return [cipher_text, encrypted_key]
  
  def get_private_key(self):
    return self.rsa.get_private_key()

  def get_public_key(self):
    return self.rsa.get_public_key()

  def decrypt(self, encrypted_text:str, encrypted_key:str, d:int, n:int):
    """ Return decrypted text and key. Argument (d,n) is the pair of private key of RSA """
    self.rsa.set_private_key(d, n)
    plain_key = self.rsa.decrypt(encrypted_key)
    self.aes = AES(plain_key)
    return self.aes.decrypt(encrypted_text), plain_key

  # def decrypt_file(self, encrypted_text:str, encrypted_key:str, d:int, n:int):
  #   """ Return decrypted file as hex and key. Argument (d,n) is the pair of private key of RSA """
  #   self.rsa.set_private_key(d, n)
  #   plain_key = self.rsa.decrypt(encrypted_key)
  #   self.aes = AES(plain_key)
  #   return self.aes.decrypt_file(encrypted_text), plain_key

##------------------------------------------------------------------##
##------------------------- Class Definition -----------------------##
######################################################################




######################################################################
##--------------------------- Testing Code -------------------------##
##------------------------------------------------------------------##

if __name__ == '__main__':
  RSA_KEY_BIT = 16
  PLAIN_TEXT = "Lorem Ipsum is simply dummy text of the printing and typesetting industry."
  
  hcs = Hybrid_Crypto_System()

  print("Plain text     : " + PLAIN_TEXT)

  encrypted_text = hcs.encrypt(PLAIN_TEXT)
  print("Encrypted text : " + encrypted_text[0])
  print("Encrypted key  : " + encrypted_text[1])

  d, n = hcs.get_private_key()
  print("Private key    : ", d, n)

  decrypted_text = hcs.decrypt(encrypted_text[0], encrypted_text[1], d, n)
  print("Decrypted text : " + decrypted_text)

##------------------------------------------------------------------##
##--------------------------- Testing Code -------------------------##
######################################################################
