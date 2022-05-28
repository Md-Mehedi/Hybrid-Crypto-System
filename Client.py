######################################################################
##----------------------------- Imports ----------------------------##
##------------------------------------------------------------------##

import base64
import os
import socket
import sys

from AES import AES
from HybridCryptoSystem import Hybrid_Crypto_System
from RSA import RSA

##------------------------------------------------------------------##
##----------------------------- Imports ----------------------------##
######################################################################


""" This is Receiver: BOB """


######################################################################
##------------------------ Global Definition -----------------------##
##------------------------------------------------------------------##

BUFFER_SIZE = 4096
PORT = 12346
IP = '127.0.0.1'
RSA_K = 128

##------------------------------------------------------------------##
##------------------------ Global Definition -----------------------##
######################################################################




######################################################################
##------------------------- Helper Functions -----------------------##
##------------------------------------------------------------------##

def send_ack(socket):
  """ Send acknowledgement. It is called after every transmission """
  socket.send("ACK".encode())

def recv(socket):
  """ Receive data chunk by chunk. \n
  At first it receive the length of data and send an acknowledgement.
  Afterthat it iterate until whole data received. And finally sent an acknowledgement """
  data = ''
  length = int(socket.recv(20).decode())  # Receiving length of data
  send_ack(socket)                        # Sending acknowledgement
  collect_byte = 0
  while True:
    if length - collect_byte <= BUFFER_SIZE:
      fragment = socket.recv(length-collect_byte).decode()
      data += fragment
      break;
    else :
      fragment = socket.recv(BUFFER_SIZE).decode()
      data += fragment
      collect_byte += BUFFER_SIZE
  send_ack(socket)
  return data

##------------------------------------------------------------------##
##------------------------- Helper Functions -----------------------##
######################################################################



if __name__ == '__main__':
  # Connection establishing with server
  server = socket.socket()
  server.connect((IP, PORT))
  print("Connection established to server.")
  print("Waiting for reply from server...")
  print()

  # Receiving encrypted text, encrypted key and public key
  while True:
    choice = recv(server)
    if choice == '0':
      sys.exit()
    elif choice == '1':
      pass
    elif choice == '2':
      filename = recv(server)
    else: sys.exit()

    encrypted_text = recv(server)
    print("========== Information About Decryption ==========")
    print("Encrypted text : ", encrypted_text)
    encrypted_key = recv(server)
    print("Encrypted key  : ", encrypted_key)
    e = int(recv(server))
    n = int(recv(server))
    print("          e, n : ", e, n)

    # Initializing file and folder path
    dirname = os.path.dirname(__file__)
    secret_folder_path = dirname + "\\Don't open this"
    private_key_file_path = secret_folder_path + "\\private_key.txt"
    decrypted_file_path = secret_folder_path + "\\decrypted_text.txt"
    
    # If secret folder doesn't exist, create one
    if os.path.exists(secret_folder_path) == False :
      os.mkdir(secret_folder_path)

    # Checking if secret file is exist. If doesn't exist terminate the execution
    if os.path.exists(private_key_file_path) == False:
      print("Secret file not found")
      sys.exit()

    # Reading private key from secret file
    file = open(private_key_file_path, 'r')
    line = file.readline()
    d, n = line.split(" ")
    file.close()
    print("          d, n : ", d, n)
    
    # Decrypting
    hcs = Hybrid_Crypto_System(RSA_K)
    decrypted_text, decrypted_key = hcs.decrypt(encrypted_text, encrypted_key, int(d), int(n))
    # decrypted_text, decrypted_key = hcs.decrypt(encrypted_text, encrypted_key, int(d), int(n)) if choice=='1' else hcs.decrypt_file(encrypted_text, encrypted_key, int(d), int(n))
    print("    Plain text : ", decrypted_text)
    print("           Key : ", decrypted_key)
    print("========== Information About Decryption ==========")
    print()

    # Writing decrypted text to a file to match by the sender
    if choice == '1':
      file = open(decrypted_file_path, 'w+')
      file.write(str.strip(decrypted_text))
      file.close()
      send_ack(server)
      print("Writing complete to file for Alice confirmation")
    elif choice == '2':
      filepath = secret_folder_path + "/" + filename
      file = open(filepath, 'wb')
      x = base64.b64decode(decrypted_text)
      file.write(x)
      file.close()
      send_ack(server)
      print("Sent acknowledgement for Alice confirmation")

  server.close()
