######################################################################
##----------------------------- Imports ----------------------------##
##------------------------------------------------------------------##

import time
from math import gcd
from typing import List

from Prime import Prime

##------------------------------------------------------------------##
##----------------------------- Imports ----------------------------##
######################################################################




######################################################################
##------------------------- Helper Functions -----------------------##
##------------------------------------------------------------------##

def extended_euclidean_gcd(a:int, b:int, pair:List) -> int:
  """ Solves the equation : ax + by = gcd(a, b)  \n
    This function generate the value of x and y which satisfy the above equation for given 'a' and 'b'. \n
    Return the GCD of 'a' and 'b' and assign the value of x and y in the 'pair'  """
  if b==0 :
    pair.append(1)
    pair.append(0)
    return a
  new_pair:List[int] = []
  d = extended_euclidean_gcd(b, a%b, new_pair)
  pair.append(new_pair[1])
  pair.append(new_pair[0] - new_pair[1]*(a//b))
  return d

def exponential_mod(a:int, b:int, m:int):
  """ return a^b mod m    \n
    Used binary exponentiation to build the result """
  res = 1;
  while (b > 0):
    if (b & 1):
      res = (res * a) % m
    a = (a * a) % m
    b >>= 1
  return res;

##------------------------------------------------------------------##
##------------------------- Helper Functions -----------------------##
######################################################################




######################################################################
##------------------------- Class Definition -----------------------##
##------------------------------------------------------------------##

class RSA:

  prime_p = 13
  prime_q = 11

  public_key = []
  private_key = []

  # Time calculating variables
  __key_generation_time = 0
  __encryption_time = 0
  __decryption_time = 0

  KEY_BIT_COUNT = 16      # Default value

  def __init__(self, key_bit:int=16) -> None:
    self.KEY_BIT_COUNT = key_bit
    self.key_generation()

  def get_e(self, phi:int):
    """ Return e such that 1<e<phi and be a coprime with phi """
    for e in range(2, phi):
      if gcd(e, phi) == 1:
        return e

  def get_public_key(self) -> List:
    return self.public_key

  def get_private_key(self) -> List:
    return self.private_key

  def get_key_generation_time(self) -> float:
    return self.__key_generation_time

  def get_encryption_time(self) -> float:
    return self.__encryption_time
  
  def get_decryption_time(self) -> float:
    return self.__decryption_time

  def set_private_key(self, d:int, n:int) -> None:
    self.private_key = [int(d), int(n)]
  
  def generate_prime(self):
    """ Generate two prime number p and q by using Prime class """
    prime = Prime()
    self.prime_p = prime.get_prime_of_bit(self.KEY_BIT_COUNT/2)
    self.prime_q = prime.get_prime_of_bit(self.KEY_BIT_COUNT/2)
    while self.prime_p == self.prime_q:
      self.prime_q = prime.get_prime_of_bit(self.KEY_BIT_COUNT/2)
    
  def key_generation(self):
    """ 
    Takes bit count 'N' of prime number and it does the following tasks:
    1.  Select two prime numbers p and q 
    2.  Calculate n = p*q
    3.  Calculate phi(n) = (p-1)*(q-1)
    4.  Select e, such that e is relative prime of phi(n)
    5.  Calculate d, such that e*d = 1 mod phi(n)
    6.  Public key: {e,n} and Private key: {d,n} 
    """
    self.__key_generation_time = time.time()
    self.generate_prime()                         # # Select two prime numbers p and q 
    n = self.prime_p * self.prime_q               # Calculate n = p*q
    phi = (self.prime_p-1) * (self.prime_q-1)     # Calculate phi(n) = (p-1)*(q-1)
    e = self.get_e(phi)                           # Select e, such that e is relative prime of phi(n)
    pair = []
    extended_euclidean_gcd(e, phi, pair)
    d = pair[0]                                   # Calculate d, such that e*d = 1 mod phi(n)
    if d<0:                                       # Checking if d is negative, then makes it positive
      d = d + phi
    self.public_key = [e, n]
    self.private_key = [d, n]
    self.__key_generation_time = time.time() - self.__key_generation_time
    if DEBUG :                                    # Used for debugging purpose
      print("Prime -> P = ", self.prime_p)
      print("Prime -> Q = ", self.prime_q)
      print("n   = ", n)
      print("phi = ", phi)
      print("e   = ", e)
      print("d   = ", d)
      print("Public key : ", self.public_key)
      print("Private key : ", self.private_key)
    
  def encrypt(self, plain_text:str):
    """ Return an encrypted string which contains number separating with space of corresponding character of 'plain_text' """
    self.__encryption_time = time.time()
    encrypted_text = ""
    for ch in plain_text:
      encrypted_text += str(exponential_mod(ord(ch), self.public_key[0], self.public_key[1])) + " "
    self.__encryption_time = time.time() - self.__encryption_time
    return encrypted_text

  def decrypt(self, encrypted_text:str):
    """ Return decrypted plain text using private key generated with public key of encrypted text """
    self.__decryption_time = time.time()
    numbers = encrypted_text.split(" ")
    decrypted_text = ""
    for value in numbers:
      if value != "":
        decrypted_text += chr(exponential_mod(int(value), self.private_key[0], self.private_key[1]))
    self.__decryption_time = time.time() - self.__decryption_time
    return decrypted_text

##------------------------------------------------------------------##
##------------------------- Class Definition -----------------------##
######################################################################




######################################################################
##--------------------------- Testing Code -------------------------##
##------------------------------------------------------------------##

DEBUG = False

if DEBUG :
  RSA_KEY_BIT = 128
  PLAIN_TEXT = "Hello!!! Now text can be Encrypt and Decrypt by RSA class"
  print("Plain text     : " + PLAIN_TEXT)
  rsa_encrypt = RSA(RSA_KEY_BIT);
  encrypted_text = rsa_encrypt.encrypt(PLAIN_TEXT)
  print("Encrypted text : " + encrypted_text)

  rsa_decrypt = rsa_encrypt
  decrypted_text = rsa_decrypt.decrypt(encrypted_text)
  print("Decrypted text : " + decrypted_text)

if __name__ == '__main__':
  print("Enter text : ")
  plain_text = input()
  print("K\tMatched\tKey-Generation\t\t\tEncryption\t\t\tDecryption")
  for K in {16, 32, 64, 128}:
    rsa = RSA(K)
    cipher_text = rsa.encrypt(plain_text)
    decipher_text = rsa.decrypt(cipher_text)
    # print("Cipher text : ", cipher_text)
    # print("Decipher text : ", decipher_text)
    print(f"{K} \t{'Yes' if plain_text == decipher_text else 'No'}\t{rsa.get_key_generation_time()}\t\t{rsa.get_encryption_time()}\t\t{rsa.get_decryption_time()}")

##------------------------------------------------------------------##
##--------------------------- Testing Code -------------------------##
######################################################################
