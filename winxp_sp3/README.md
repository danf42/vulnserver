# Vulnserver Proof of Concepts for Windows XP SP3

## Fuzzing
This directory contains all the Spike files used to fuzz the different commands.  14 different inputs were fuzzed, but only 6 were found to cause the application to crash.     

## GMON
Analysis of the gmon crash showed that this buffer overwrite was a standard Structured Exception Handler (SEH) overwrite.  The following proof of concepts were developed to exploit the gmon command:
 - Egghunter - Jump back 48 bytes into the 'A' buffer to hit a nop sled containing our egghunter shellcode.  Our reverse shell is placed at the begining of the 'A' buffer.  
 - Phrack Jump - Using the jump instructions identified in [Phrack JMP (Issue 62, Article 7)](http://phrack.org/issues/62/7.html), jump back into the 'A' buffer 48 bytes, hit a nop sled, and then hit the Phrack jump code that jumps back approximately 800 bytes.  This will hit a nop sled that leads to execution of the reverse shell.  
 - Long Jump approach - There are 19 bytes after the SEH that we can control.  By using a short jump, we can jump into these bytes which will jump us back up the stack into a nop sled and hit our reverse shell
 - Stack Pivot - If we adjust the stack, we can hit an address that is a pointer into the 'A' buffer.  We can adjust the stack pointer to move to this location, jump to the address being pointed to, and then execution a reverse shell.  

## GTER
Analysis of the gter crash showed that we have a limited buffer to try to exploit.  The following proof of concepts were developed to exploit the gter command:
 - Egghunter - Send our reverse shell to a non-vulnerable command so that it is received and stored in memory.  Send our egghunter to the GTER command and wait for the reverse shell to be found and executed.  
 - Socket Reconstruction - By reusing the libraries already loaded to create the initial socket, we can create another socket to accept a larger payload.  We will use this to receive our reverse shell.  
 - Custom Reverse shell - By reusing the networking libraries already loaded, we can create a custom reverse shell to fit into the 147 byte buffer space.  

## HTER
Analysis of the hter crash showed that this comman reads in the literal value of the buffer instead of converting it to hex.  Before sending a malicous payload, we need to convert it into it's hex representation.  The following proof of concepts were developed to exploit the hter command:
 - Using a `jmp eax` - EAX points to the begining of our buffer.  Using a jmp/call eax instruction, we can jump to our reverse shell.  
 - Using a `jmp esp` - ESP points to the next instructions after EIP is over written.  We can use a jmp esp instruction to jump to our reverse shell

## KSET
Analysis of the kset crash showed that this is another limited buffer to overwrite.  The following proof of concepts were developed to exploit the kset command:
 - Socket Reuse - Find the socket descriptor that initially gets setup.  Once found, we can reuse the descriptor to pass to our own receive function.  This allows us to send a larger payload, such as the reverse shell.  
 - Egghunter - Send our reverse shell to a non-vulnerable command do that it is received and stored into memory.  We then send our egghunter to the KSET command and wait for the reverse shell to be found and executed.  

## LTER
Analysis of the lter crash showed only alphanumeric characters are allowed.  The following proof of concepts were developed to exploit the lter command:
 - Egghunter - Use the [sub encoder](https://github.com/danf42/vulnserver/tree/master/custom_tools/encoder) to encode the egghunter shellcode.  We can use `msfvenom` to encode our reverse shell and will need to use the `BufferRegister` option to specifiy where are shellcode is located.  This is because the first few bytes of the encoded reverse shell is not alphanumeric safe.   
 - Using a `jmp esp` - Found that if you send a small enough payload, you will not trigger the SEH.  We can use the [safe address checker](https://github.com/danf42/vulnserver/tree/master/custom_tools/safe_address_checker) to find a `jmp esp` instruction that only contains alphanumeric characters.  We can use `msfvenom` to encode our reverse shell and will need to use the `BufferRegister` option to specifiy where are shellcode is located.

## TRUN
Analysis of the trun crash showed that this was a standard buffer overwrite vulnerability.  We used this command to experiment with writing Windows API shellcode and with trying to bypass strict firewall rules.  
 - Standard buffer overwrite - Find a `jmp esp` instruction to jump to our reverse shell
 - Add User - Add user via System, WinExec, and Windows API
 - Disable Firewall - Disablable the Windows Firewall using Winexec, System, and Registry API calls.  
 - Enable RDP - Enable RDP using Winexec and System calls
 - Hello World Message Box - Use the Windows API to display a message box that says 'Hello World'
 - Pop Calc - Execute Windows Calc using Winexec and System calls 
 - Custom Shells - custom bind and reverse shell using Windows API
 - Rebind - Use Borja Merino's [Migrate + Rebind socket](https://github.com/BorjaMerino/Windows-One-Way-Stagers/blob/master/Rebind-Socket/migrate_rebind_socket.asm) to spawn a suspended copy of the application with our bind shell, terminate the 
 current application, sleep to ensure the old sockets are cleaned up, and then execute our cloned copy.  This is to bypass strict firewall rules that only allow the application to communicate externally.  

    We modified Metasploit's Windows bind_tcp shellcode to sleep for 30 seconds.  
 ```
    # Added 30 second sleep for rebind shellcode
    xor eax, eax          ; zero out eax
    push eax
    push 0x7530       ; push 30 seconds (30,000 ms) onto the stack
    push #{Rex::Text.block_api_hash('kernel32.dll', 'Sleep')}
    call ebp
```  

 - Socket Reuse with Rebind - Use socket reuse to write our own receive function to receive the Rebind shellcode.  

## Resources
 - [Retro shellcoding for current threats: rebinding sockets in Windows](https://www.shelliscoming.com/2019/11/retro-shellcoding-for-current-threats.html)
