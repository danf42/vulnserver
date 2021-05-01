# Vulnserver 

[Vulnserver](https://github.com/stephenbradshaw/vulnserver) is an intentionally vulnerable application to help learn about exploiting buffer overflows.  I used this vulnerable app to help practice writing assembly code, fuzzing, and writing exploits for various types of buffer overflows.   

## Repository Overview

This repository contains all of the custom developed tools and proof of concept exploits I've created while working through Vulnserver. 

### Custom Tools
Tools I have developed to facilitate proof of concept development against Vulnserver.  
 - [chunk_file](custom_tools/chunk_file) - Split an executable in half to help narrow down the the section that is triggering Anitvirus
 - [compile_assembly](custom_tools/compile_assembly) - Modified script from PentesterAcademy's [x86 Assembly Language and Shellcoding on Linux](https://www.pentesteracademy.com/course?id=3). Script will check for null characters and output shellcode.    
 - [encoder](custom_tools/encoder) - Alphanumeric Sub-Encoder developed from Metasploit's opt_sub.rb encoder and Corelan's Mona encoder.  
 - [fuzzing](custom_tools/fuzzing) - Python script to automate fuzzing multiple commands using Spike Fuzzer.  Does require a modification to Spike source code.    
 - [safe_address_checker](custom_tools/safe_address_checker) - Python script that will validate a list of addresses against a set of good characters.
 - [str_to_hex](str_to_hex) - Python scripts that will generate x86 assembly instructions for a list of strings.  

### WinXP SP3
My initial focus was attacking Vulnserver installed on a Windows XP SP3 VM.
 - [fuzzing](winxp_sp3/fuzzing) - Spike scripts used to fuzz Vulnserver's commands
 - [gmon](winxp_sp3/gmon) - Standard Structured Exception Handler (SEH) buffer overwrite
 - [gter](winxp_sp3/gter) - Limited buffer size
 - [hter](winxp_sp3/hter) - Reads in literal value of buffer  
 - [kset](winxp_sp3/kset) - Limited buffer size
 - [lter](winxp_sp3/lter) - Restricted character set; Only Alphanumeric characters allowed 
 - [trun](winxp_sp3/trun) - Straigt foward buffer overwrite.  This command was used to learn about Windows API programming using x86 assembly langauge.  

### x86 Dynamic Addresses
This section uses Stephen Fewer's hashing algorithm to dynamically find addresses for the Windows API methods to use against each Vulnserver command.
 - [Custom Reverse Shell](x86_dynamic_addresses/rev_shell) - Custom Reverse shell using CreateProcessA
 - [Port Rebind Shell](x86_dynamic_addresses/rebind_bind_shell) - Firewall bypass, Use port rebind technique to launch custom bind shell.  
 - [Address Reuse Shell](x86_dynamic_addresses/port_reuse_bind_shell) - Firewall bypass, Use address reuse technique to bind to physical address and port used by Vulnserver to launch a custom bindshell.  
 - [Custom Bind Shell](x86_dynamic_addresses/bind_shell) - Custom bind shell using CreateProcessA
 - [Add User, Enable RDP](x86_dynamic_addresses/add-user_rdp) - Use Windows API to create a new users, add them to local administrator's group, and enable RDP
 - [Add Use, Enable RDP via System()](x86_dynamic_addresses/add-user_firewall_rdp_system) - Use System() to create a new users, add them to local administrator's group, and enable RDP

## To-Do
 - Upgrade all the tools and exploits to Python3
 - Practice against newer Windows Operating Systems
 - Practice with mitigation controls enabled, such as DEP, ASLR, and strict firewall rules
 
## Resources
 - [Metasploit's Sub Encoder (optimised)](https://github.com/rapid7/metasploit-framework/blob/master//modules/encoders/x86/opt_sub.rb)
 - [Mona MnEncoder Class](https://github.com/corelan/mona)
 - [Vulnserver](https://github.com/stephenbradshaw/vulnserver)
