import socket
import subprocess
import os
import argparse

##
#
# This program utilizes a modified version of spike.  spike was modified to exit if the connection to the program times outs
# spike.c was modified
#    case 1: /*TCP*/
#      {
#      if (current_spike->fd==-1)
#        {
#          printf("tried to send to a closed socket!\n");
#          // return 0;
#          exit(1);
#        }
#
#root@bt:/pentest/fuzzers/spike/src# diff spike.c spike.c.orig 
#1085,1086c1085
#< 	  // return 0;
#<           exit(1);
#---
#> 	  return 0;
#1164,1165c1163
#< 	  //return 0;
#<           exit(1);
#---
#> 	  return 0;
#
##

def is_service_alive(ip_addr, port):
 
    is_alive = True 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)

    try:
        s.connect((ip_addr, int(port)))
        print "[+] Service is alive"

    except Exception as e:
        print "[-] Failed to connect to service %s" % e
        is_alive = False

    finally:
        s.close()     

    return is_alive

def run_spike_file(ip_addr, port, spike_file, skip_var, skip_str):
    
    with open(os.devnull, 'w') as FNULL:
        proc = subprocess.Popen(['/pentest/fuzzers/spike/src/generic_send_tcp', ip_addr, port, spikefile, skipvar, skipstr], 
                                stdout=FNULL, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

        (stdout_data, stderr_data) = proc.communicate()

        proc_status = proc.wait()

def restart_application():

    raw_input("Please start the application.  Press Enter when ready")

    is_alive = is_service_alive(ip_addr, port)

    return is_alive

def run_fuzz_test(ip_addr, port, spike_file, skip_var, skip_str):

    results = None

    is_started = restart_application()
    if not is_started:
        return results

    run_spike_file(ip_addr, port, spikefile, skipvar, skipstr)

    if is_service_alive(ip_addr, port):
        print "%s did not crash application" % spikefile
        results = True
    else:
        print "%s caused application to crash" % spikefile
        results = False
     
    return results

parser = argparse.ArgumentParser(description="Driver for application fuzzer")
parser.add_argument('ipaddr', type=str, help="IP Address of application to fuzz")
parser.add_argument('port', type=str, help="Port of application to fuzz")
parser.add_argument('--spikefile', type=str, help="Spike file to run", default="all")
parser.add_argument('--skipvar', type=str, help="SKIPVAR value", default='0')
parser.add_argument('--skipstr', type=str, help="SKIPSTR value", default='0')
args = parser.parse_args()

# Get all the spike files in the directory
spike_files = [afile for afile in os.listdir(".") if afile.endswith(".spk")]

spikefile = args.spikefile
skipvar = args.skipvar
skipstr = args.skipstr
ip_addr = args.ipaddr 
port = args.port 

crash_list = []
nocrash_list = []

test_results = []

print "Starting fuzzer..."    

if spikefile == 'all':
        
    for spikefile in spike_files:

        print "Running %s spike file" % spikefile

        results = run_fuzz_test(ip_addr, port, spikefile, skipvar, skipstr)  
            
        if results != None:
            test_results.append((spikefile, results))
else:
    if spikefile in spike_files:
        print "Running %s spike file" % spikefile
        
        results = run_fuzz_test(ip_addr, port, spikefile, skipvar, skipstr)
        if results != None:
            test_results.append((spikefile, results))
    else:
        print "%s is not a reconginzed spike file, Exiting..."

for afile, status in test_results:
    if status:
        nocrash_list.append(afile)
    else:
        crash_list.append(afile)

print "Commands that caused a crash %s" % ' '.join(crash_list)

print "Commands that did not cause a crash %s" % ' '.join(nocrash_list)
