import socket
import sys
import re
from  _thread import *
import time
import os,binascii

FLAG = ''
SECRET = 'z1gz4G'
HOST = ''
PORT = 1337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print ('Socket created')

try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print ('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()

print ('Socket bind complete')

s.listen(10)
print ('Socket now listening')

def clientthread(conn):
    chall = conn.recv(1024)

    chall_xored = xor_two_str(chall.decode().strip(),SECRET)

    conn.sendall(chall_xored.encode())

    FLAG = conn.recv(1024)

    print (FLAG.strip())

    time.sleep(2)
    conn.close()


def xor_two_str(a,b):
    return ''.join([hex(ord(a[i%len(a)]) ^ ord(b[i%(len(b))]))[2:] for i in range(max(len(a), len(b)))])

while 1:
    conn, addr = s.accept()
    print ('Connected with ' + addr[0] + ':' + str(addr[1]))

    start_new_thread(clientthread ,(conn,))

s.close()