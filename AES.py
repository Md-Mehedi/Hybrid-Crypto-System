# -*- coding: utf-8 -*-

######################################################################
##----------------------------- Imports ----------------------------##
##------------------------------------------------------------------##

import copy
import time
from array import array
from asyncio import tasks
from collections import deque
from typing import List

from BitVector import *

##------------------------------------------------------------------##
##----------------------------- Imports ----------------------------##
######################################################################




######################################################################
##------------------------ Global Definition -----------------------##
##------------------------------------------------------------------##

TOTAL_ROUND = 10

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

RCon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x66]

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

AES_modulus = BitVector(bitstring='100011011')

##------------------------------------------------------------------##
##------------------------ Global Definition -----------------------##
######################################################################




######################################################################
##------------------------- Helper Functions -----------------------##
##------------------------------------------------------------------##

def print_bv_matrix(matrix:List[List[BitVector]]) -> None:
  """ Print BitVector object converting to Uppercase Hexadecimal as matrix format """
  for row in matrix:
    for value in row:
      print(str.upper(value.get_bitvector_in_hex())," ", end="")
    print()
  print()

def transpose(matrix:List[List[BitVector]]) -> None:
  """ Convert the matrix to it's transpose form.          \n
      It iterate only upper trianguler of matrix and swap row and column """
  for i in range(len(matrix)):
    for j in range(i+1, len(matrix[i])):
      temp = matrix[i][j]
      matrix[i][j] = matrix[j][i]
      matrix[j][i] = temp

def array_xor(ara1:List[BitVector], ara2:List[BitVector]) -> List[BitVector]:
  """ Return a list containing xor value of corresponding index value of given two list
      If length of given lists doesn't equal, return a list of length of shorter list """
  result = []
  n = min(len(ara1), len(ara2))
  for i in range(n):
    result.append(ara1[i] ^ ara2[i])
  return result

def sub_byte_from_sbox(ara:List[BitVector]) -> None:
  """ Substitute bytes from SBox """  
  for i in range(len(ara)):
      ara[i] = BitVector(intVal=Sbox[ara[i].intValue()], size=8);

def sub_byte_from_inv_sbox(ara:List[BitVector]) -> None:
  """ Substitute bytes from Inverse SBox """
  for i in range(len(ara)):
      ara[i] = BitVector(intVal=InvSbox[ara[i].intValue()], size=8);

def rotate(array: List, n: int) -> None:
  """ Rotate the list by value n. 
      Positive value of n makes right circular shift 
      and negative value of n makes left circular shift """
  temp = deque(array);
  temp.rotate(n)
  array.clear()
  array.extend(list(temp))

##------------------------------------------------------------------##
##------------------------- Helper Functions -----------------------##
######################################################################




######################################################################
##------------------------- Class Definition -----------------------##
##------------------------------------------------------------------##

class AES:
  __KEY:str = ""      # Default Key
  __w:List[List[BitVector]] = []     #2D array
  __state_matrix:List[List[BitVector]] = []

  __key_scheduling_time = 0
  __encryption_time = 0
  __decryption_time = 0

  def __init__(self, key:str="Thats my Kung Fu") -> None:
    """ Takes a string as a key. If no key passes "Thats my Kung Fu" is used as key """
    self.set_key(key)

  def set_key(self, key):
    while len(key) < 16 : 
      key += " "
    self.__KEY = key
  
  def get_key_scheduling_time(self):
    return self.__key_scheduling_time
    
  def get_encryption_time(self):
    return self.__encryption_time

  def get_decryption_time(self):
    return self.__decryption_time

  def print_state(self) -> None:
    """ Print the state matrix """
    print_bv_matrix(self.__state_matrix)
  
  def text_to_hex(self, text:str) -> None:
    """ Return ASCII text to Hexadecimal string """
    val = BitVector(textstring=text)
    hex_value = val.get_bitvector_in_hex();
    return hex_value

  def hex_to_text(self, hex:str) -> str:
    text = ''
    for i in range(len(hex)//2):
      text += BitVector(hexstring=hex[2*i:2*i+2]).get_bitvector_in_ascii()
      
    return text

  def hex_to_matrix(self, hex_value:str) -> List[List[BitVector]]:
    """ Return a 2D matrix from Hexadecimal string. Each cell contain 2 Hex character means 1 byte. """
    array = []
    for i in range(4):
      temp = []
      for j in range(4):
        temp.append(BitVector(hexstring=hex_value[(i*8+j*2):(i*8+j*2+2)]))  # Taking substring of 2 character 
      array.append(temp)
    return array
  
  def hex_matrix_to_text(self, matrix:List[List[BitVector]]) -> str:
    """ Convert hexadecimal matrix to uppercase string format """
    text = ""
    for row in matrix:
      for val in row:
        text += str.upper(val.get_bitvector_in_hex())
    return text

  def get_key(self, n:int) -> List[BitVector]:
    """ Return a 2D matrix of key at round n from w which is generated by Key Expansion """
    result = self.__w[n*4:n*4+4]
    transpose(result)
    return result

  def g(self, row:List[BitVector], round_count:int) -> List[BitVector]:
    """ Uses in Key Expansion. This method do following tasks:
        1.  Circular left rotate by 1
        2.  Substitution bytes from SBox
        3.  Add with Round Constant """
    row_temp = copy.deepcopy(row)
    rotate(row_temp, -1)                              # Circular left rotate by 1
    sub_byte_from_sbox(row_temp)                      # Substitution bytes from SBox
    
    round_constant = [
      BitVector(intVal=RCon[round_count]),            # Round constant is different for different round
      BitVector(intVal=0, size=8),
      BitVector(intVal=0, size=8),
      BitVector(intVal=0, size=8)
    ]
    row_temp = array_xor(row_temp, round_constant)    # Add with Round Constant
    return row_temp

  def key_expansion(self) -> None:
    """ This method do following tasks:
        1.  Convert the ASCII text string to Hexadecimal string
        2.  Split by 2 character and make a 4x4 print_bv_matrix
        3.  By looping generate keys for different round
        4.  Uses g() after 4 iteration """
    self.__key_scheduling_time = time.time()
    
    hex_key = self.text_to_hex(self.__KEY)              # Convert the ASCII text string to Hexadecimal string
    self.__w = self.hex_to_matrix(hex_key);             # Split by 2 character and make a 4x4 print_bv_matrix
    
    round_count = 0
    for i in range(4, 4*TOTAL_ROUND+4):               # By looping generate keys for different round
      temp = []
      if(i%4==0):
        temp = array_xor(self.__w[i-4], self.g(self.__w[i-1], round_count=round_count))   # Uses g() after 4 iteration
        round_count = round_count + 1
      else:
        temp = array_xor(self.__w[i-1], self.__w[i-4])
      self.__w.append(temp)
    self.__key_scheduling_time = time.time() - self.__key_scheduling_time

  def create_state_matrix(self, hex_value:str) -> None:
    """ Create state matrix from the Hexadecimal string """
    self.__state_matrix = self.hex_to_matrix(hex_value)
    transpose(self.__state_matrix)

  def sub_bytes(self) -> None:
    """ Used for Encryption. Substitute value from SBox to whole state matrix """
    for i in range(4):
      sub_byte_from_sbox(self.__state_matrix[i])

  def inv_sub_bytes(self) -> None:
    """ Used for decryption. Substitute value from Inverse SBox to whole state matrix """
    for i in range(4):
      sub_byte_from_inv_sbox(self.__state_matrix[i])

  def shift_row(self) -> None:
    """ Used for Encryption. Shift rows at left """
    for i in range(4):
      rotate(self.__state_matrix[i], -i)
      
  def inv_shift_row(self) -> None:
    """ Used for Decryption. Shift rows at right """
    for i in range(4):
      rotate(self.__state_matrix[i], i)

  def mix_column(self) -> None:
    """ Used for Encryption. Matrix multiplication of State Matrix and Mixer. 
        But Galois Field multiplication is used for multiplication and xor for addition """
    temp_matrix = copy.deepcopy(self.__state_matrix)
    for i in range(4):
      for j in range(4):
        sum = BitVector(intVal=0, size=8)
        for k in range(4):
          sum = sum ^ (Mixer[i][k].gf_multiply_modular(temp_matrix[k][j], AES_modulus, 8))        # Galois Field multiplication
        self.__state_matrix[i][j] = sum
        
  def inv_mix_column(self) -> None:
    """ Used for Decryption. Matrix multiplication of State Matrix and Inverse Mixer. 
        But Galois Field multiplication is used for multiplication and xor for addition """
    temp_matrix = copy.deepcopy(self.__state_matrix)
    for i in range(4):
      for j in range(4):
        sum = BitVector(intVal=0, size=8)
        for k in range(4):
          sum = sum ^ (InvMixer[i][k].gf_multiply_modular(temp_matrix[k][j], AES_modulus, 8))     # Galois Field multiplication
        self.__state_matrix[i][j] = sum
  
  def add_round_key(self, round_count:int) -> None:
    """ Add (xor) the Round Key to the State Matrix """
    key_matrix = self.get_key(round_count)
    for i in range(4):
      self.__state_matrix[i] = array_xor(self.__state_matrix[i], key_matrix[i])

  def encrypt(self, plain_text: str, count:int=-1) -> str:
    """ Return encrypted text as ASCII string """
    self.__encryption_time = time.time()
    if count != -1:
      plain_text = plain_text[0:count]
    while len(plain_text) % 16 !=0:
      plain_text += " "
    result = ""
    n = len(plain_text)/16
    for i in range(int(n)):
      result += self.encrypt_segment(plain_text[i*16:(i+1)*16])
    self.__encryption_time = time.time() - self.__encryption_time
    return result
    
  def decrypt(self, encrypted_text:str) -> str:
    """ Return decrypted plain text in ASCII format """
    self.__decryption_time = time.time()
    result = ""
    n = len(encrypted_text)/(16*2)
    for i in range(int(n)):
      result += self.decrypt_segment(encrypted_text[i*16*2:(i+1)*16*2])
    self.__decryption_time = time.time() - self.__decryption_time
    return result

  def encrypt_segment(self, plain_text:str) -> str:
    """ Return encrypted text as ASCII string """
    text_hex = self.text_to_hex(plain_text)
    self.create_state_matrix(text_hex)
    self.key_expansion()
    self.add_round_key(0)
    for i in range(1, TOTAL_ROUND+1):
      self.sub_bytes()
      self.shift_row()
      if(i != TOTAL_ROUND):
         self.mix_column()
      self.add_round_key(i)
    transpose(self.__state_matrix)
    return self.hex_matrix_to_text(self.__state_matrix)   # Converting Hexadecimal matrix to text

  def decrypt_segment(self, encrypted_text:str) -> None:
    """ Return decrypted plain text in ASCII format """
    self.create_state_matrix(encrypted_text)
    self.key_expansion()
    self.add_round_key(TOTAL_ROUND)
    for i in reversed(range(0, TOTAL_ROUND)):
      self.inv_shift_row()
      self.inv_sub_bytes()
      self.add_round_key(i)
      if i!=0:
        self.inv_mix_column()
    transpose(self.__state_matrix)
    dec_hex = self.hex_matrix_to_text(self.__state_matrix)
    bv = BitVector(hexstring=dec_hex)
    return bv.get_bitvector_in_ascii()

##------------------------------------------------------------------##
##------------------------- Class Definition -----------------------##
######################################################################




######################################################################
##--------------------------- Testing Code -------------------------##
##------------------------------------------------------------------##

TESTING = False

if TESTING :
  PLAIN_TEXT = "Hello!!! Now text can be Encrypt and Decrypt by AES class"
  print("Plain text     : " + PLAIN_TEXT)
  aes_encrypt = AES("Thats my Kung Fu");
  encrypted_text = aes_encrypt.encrypt(PLAIN_TEXT)
  print("Encrypted text : " + encrypted_text)

  aes_decrypt = AES("Thats my Kung Fu");
  ptext = aes_decrypt.decrypt(encrypted_text)
  print("Decrypted text : " + ptext)

if __name__ == '__main__':
  aes = AES()

  print("Plain Text:")
  plain_text = input()
  print(aes.text_to_hex(plain_text))

  print("\nKey:")
  key = input()
  print(aes.text_to_hex(key))

  aes.set_key(key)
  cipher_text = aes.encrypt(plain_text, 16)
  print("\nCipher Text:")
  print(cipher_text, "[In HEX]")
  print(aes.hex_to_text(cipher_text), "[In ASCII]")

  deciphered_text = aes.decrypt(cipher_text)
  print("\nDeciphered Text:")
  print(aes.text_to_hex(deciphered_text), "[In HEX]")
  print(deciphered_text, "[In ASCII]")

  print("\nExecution Time")
  print("Key Scheduling: ", aes.get_key_scheduling_time(), "seconds")
  print("Encryption Time: ", aes.get_encryption_time(), "seconds")
  print("Decryption Time: ", aes.get_decryption_time(), "seconds")

##------------------------------------------------------------------##
##--------------------------- Testing Code -------------------------##
######################################################################
