######################################################################
##----------------------------- Imports ----------------------------##
##------------------------------------------------------------------##

import os
import socket

from AES import AES
from RSA import RSA

##------------------------------------------------------------------##
##----------------------------- Imports ----------------------------##
######################################################################

""" This is Sender: ALICE """


######################################################################
##------------------------ Global Definition -----------------------##
##------------------------------------------------------------------##

BUFFER_SIZE = 4096
PORT = 12346

##------------------------------------------------------------------##
##------------------------ Global Definition -----------------------##
######################################################################




######################################################################
##------------------------- Helper Functions -----------------------##
##------------------------------------------------------------------##

def recv_ack(socket):
  """ Received acknowledgement as "ACK". If text mismatch return False otherwise True """
  if socket.recv(4).decode() != 'ACK': 
    print("Acknowledge not found")
    return False
  return True

def send(socket, msg):
  """ Send anything converting to bytes as chunk by chunk.\n
  At first send the length of the message and wait for ACKNOWLEDGE
  Message send as chunk by chunk size of BUFFER_SIZE. Finally wait for ACKNOWLEDGE """
  msg = str(msg)
  sent_byte = 0
  socket.send(str(len(msg)).encode())   # Sending msg length
  if not recv_ack(socket): return       # Check for acknowledgement
  while True:
    if len(msg) - sent_byte <= BUFFER_SIZE :
      socket.send(msg[sent_byte:].encode())
      break
    else :
      socket.send(msg[sent_byte:sent_byte+BUFFER_SIZE].encode())
      sent_byte += BUFFER_SIZE
  if not recv_ack(socket): return

##------------------------------------------------------------------##
##------------------------- Helper Functions -----------------------##
######################################################################

if __name__ == '__main__':
  # Server connection establishing
  server = socket.socket()        
  print ("Socket successfully created")
  server.bind(('', PORT))        
  print ("socket binded to %s" %(PORT))
  server.listen(5)    
  print ("socket is listening")
  client, addr = server.accept()    
  print ('Got connection from', addr )
  print()

  # Take input of text and AES, RSA initialization
  PLAIN_TEXT = "Offline r valo lage na"
  KEY = "Val lage na"
  aes = AES(KEY)
  rsa = RSA(16)

  # Encrypting
  encrypted_text = aes.encrypt(PLAIN_TEXT)
  encrypted_key = rsa.encrypt(KEY)
  e, n = rsa.get_public_key()
  d, n = rsa.get_private_key()

  # Initializing file and folder path
  dirname = os.path.dirname(__file__)
  secret_folder_path = dirname + "\\Don't open this"
  secret_file_path = secret_folder_path + "\\private_key.txt"
  decrypted_file_path = secret_folder_path + "\\decrypted_text.txt"

  # If secret folder doesn't exist, create one
  if os.path.exists(secret_folder_path) == False :
    os.mkdir(secret_folder_path)

  # Writing private key in a secret file
  file = open(secret_file_path, 'w+')
  file.write(str(d) + " " + str(n))
  file.close()

  print("========== Information About Encryption ==========")
  print("    Plain text : ", PLAIN_TEXT)
  print("           Key : ", KEY)
  print("Encrypted text : ", encrypted_text)
  print(" Encrypted key : ", encrypted_key)
  print("          e, n : ", e, n)
  print("          d, n : ", d, n)
  print("========== Information About Encryption ==========")
  print()

  # Sending encrypted text, encrypted key and public key
  send(client, encrypted_text)
  send(client, encrypted_key)
  send(client, e)
  send(client, n)

  # Checking if decrypted text in client end is correct
  print("========== Waiting for Bob's decryption... ==========")
  if recv_ack(client) :
    file = open(decrypted_file_path, "r")
    decrypted_text:str = file.readline()
    file.close()
    print("    Plain text : ", PLAIN_TEXT)
    print("Decrypted text : ", decrypted_text)
    if decrypted_text == PLAIN_TEXT :
      print("Encryption is ok")
    else : 
      print("Encryption don't ok")

  # Closing server and client
  client.close()
  server.close()
