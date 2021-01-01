# Vulnserver 

[Vulnserver](https://github.com/stephenbradshaw/vulnserver) is an intentionally vulnerable application to help learn about exploiting buffer overflows.  It was a recommended tool to help practice the topics and techniques covered in [Offensive Security's](https://www.offensive-security.com/) Cracking the Perimeter (CTP) course. 

## Repository Overview

This repository contains all the tools I've created and proof of concept exploits while working through Vulnserver and the CTP Course.  All learning and development was done using the BackTrack VM provided with the CTP material.  Some of the tools and all of the exploits use Python2.      

### Custom Tools
Tools I developed to facilitate proof of concept development against Vulnserver and labs in the CTP course.  
 - [chunk_file](custom_tools/chunk_file) - Split an executable in half to help narrow down the the section in the file that is triggering Anitvirus
 - [compile_assembly](custom_tools/compile_assembly) - Modified script from PentesterAcademy's [x86 Assembly Language and Shellcoding on Linux](https://www.pentesteracademy.com/course?id=3). Script will check for Null characters and output shellcode.    
 - [encoder](custom_tools/encoder) - Alphanumeric Sub-Encoder developed from Metasploit's opt_sub.rb encoder and Corelan's Mona encoder.  
 - [fuzzing](custom_tools/fuzzing) - Python script to automate fuzzing multiple commands using Spike Fuzzer.  Does require a modification to Spike source code.    
 - [safe_address_checker](custom_tools/safe_address_checker) - Python script that will validate a list of addresses against a set of good characters.
 - [str_to_hex](str_to_hex) - Python script that will generate x86 assembly instructions for a list of strings.  

### WinXP SP3
My initial focus was attacking Vulnserver installed on a Windows XP SP3 VM.  All the exploits developed against Vulnserver's vulnerable commands
 - [fuzzing](winxp_sp3/fuzzing) - Spike scripts use to fuzz Vulnserver's commands
 - [gmon](winxp_sp3/gmon) - Standard Structured Exception Handler (SEH) buffer overwrite
 - [gter](winxp_sp3/gter) - Limited buffer size
 - [hter](winxp_sp3/hter) - Reads in literal value of buffer.  
 - [kset](winxp_sp3/kset) - Limited buffer size.
 - [lter](winxp_sp3/lter) - Restricted character set; Only Alphanumeric characters allowed.  
 - [trun](winxp_sp3/trun) - Straigt foward buffer overwrite.  This command was used to learn about Windows API programming using x86 assembly langauge.  

## To-Do
 - Upgrade all the tools and exploits to Python3
 - Practice against newer Windows Operating Systems
 - Practice with mitigation controls enabled, such as DEP, ASLR, and strict firewall rules
 
## Resources
 - [Metasploit's Sub Encoder (optimised)](https://github.com/rapid7/metasploit-framework/blob/master//modules/encoders/x86/opt_sub.rb)
 - [Mona MnEncoder Class](https://github.com/corelan/mona)
 - [Vulnserver](https://github.com/stephenbradshaw/vulnserver)