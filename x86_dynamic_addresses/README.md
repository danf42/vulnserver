# Dynamic Address Location x86 Shellcode

This section was my effort to learn about dynamically finding function addresses.  The shellcode utilized [Stephen Fewer's Block API hashing](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/external/source/shellcode/windows/x86/src/block/block_api.asm) algorithm to locate the function addresses.  A modified version of the [Stephen Fewer Hash calculation script](https://github.com/danf42/vulnserver/tree/master/custom_tools/metasploit_hash) was used to compute the function hashes.  The modification made resolved an issue with how the hashes were calculated for all exports from a specific DLL.   

## x86 Assembly Programs
The following programs were modified from the original Windows XP SP3 that had the function addresses hardcoded.  Please note that the code is not null free.    
  - Add user, disable firewall, enable RDP using System() call 
  - Use NetUserAdd and NetLocalGroupAddMembers to add a new user to the local administrators group.  Use RegCreateKeyExA, RegSetValueExA and RegCloseKey to enable RDP.
  - Use CreateProcessA to create a bind shell
  - Use CreateProcessA to create a reverse shell
  - Use port reuse technique and CreateProcessA to create a bind shell to the target's specific IP address application's port 
  - Use the port rebind technique and the custom bind shell to rebind to the target application's port  


## Resources
 - [Stephen Fewer's Block API hashing](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/external/source/shellcode/windows/x86/src/block/block_api.asm)
 - [Retro shellcoding for current threats: rebinding sockets in Windows](https://www.shelliscoming.com/2019/11/retro-shellcoding-for-current-threats.html)
