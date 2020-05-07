[BITS 32]

mainentrypoint:

call geteip
geteip:
pop edx ; EDX is now base for function
lea edx, [edx-5] ;adjust for first instruction?

mov ebp, esp
sub esp, 1000h

push edx
mov ebx, 0x4b1ffe8e; Kernell32.dll
call get_module_address
pop edx

push ebp
push edx
mov ebp, eax

lea esi, [EDX + KERNEL32HASHTABLE]
lea edi, [EDX + KERNEL32FUNCTIONSTABLE]
call get_api_address
pop edx
pop ebp


;TODO call your api

; Call LoadLibraryA to get user32.dll into memory
push ebp
push edx
lea eax, [EDX + USER32]
push eax
call [EDX + LoadLibraryA]
pop edx
pop ebp

; Build user32 API function pointer table
push ebp
push edx
mov ebp, eax
lea esi, [EDX + USER32HASHTABLE]
lea edi, [EDX + USER32FUNCTIONSTABLE]
call get_api_address
pop edx
pop ebp

; Call LoadLibraryA to get urlmon.dll into memory
push ebp
push edx
lea eax, [EDX + URLMON]
push eax
call [EDX + LoadLibraryA]
pop edx
pop ebp

; Build urlmon API function pointer table
push ebp
push edx
mov ebp, eax
lea esi, [EDX + URLMONHASHTABLE]
lea edi, [EDX + URLMONFUNCTIONSTABLE]
call get_api_address
pop edx
pop ebp

; call messageboxa
; says "Downloading Flower Image Now"
push 0x00 ; null byte for hi
push 0x776f4e20 ; pushing above sentence backwords
push 0x6567616d
push 0x49207265
push 0x776f6c46
push 0x20676e69
push 0x64616f6c
push 0x6e776f44
mov eax, esp ; mov pointer to eax
push 0x00 ; push utype
push 0x00 ; push lpcaption
push eax ; push lptext
push 0x00 ; push hwnd
mov ebx, edx ; trying to preseve edx
call [EDX + MESSAGEBOXA]
mov edx, ebx ; Moved back to be consistent

; call URLDownloadToFile, Downloads Flower Image over http

lea esi, [EDX + URL]
lea edi, [EDX + URLFILENAME]
push 0x00 ; push lpfnCB
push 0x00 ; Reserved, must be 0
push edi ; push szFileName
push esi ; push szURL
push 0x00 ; push pcaller
call [EDX + URLDOWNLOADTOFILE]
mov edx, ebx ; Moved back to be consistent


; CreateProcessA to open MSPaint of Flower.jpg
push 0x00 ; Pushing enough space for pointers
push 0x00
push 0x00
push 0x00
push 0x00
push 0x00
push 0x00
push 0x00
push 0x00
push 0x00
push 0x00
push 0x00
push 0x00
push 0x00
push 0x00
push 0x00
push 0x00
mov eax, esp
push 0x00 ; pushing enough space for pointers
push 0x00
push 0x00
push 0x00
mov ebx, esp
lea esi, [EDX + EXE]
push ebx ; push lpProcessInformation
push eax ; push lpStartupInfo
push 0x00 ; push lpCurrentDirectory
push 0x00 ; push lpEnvironment
push 0x00 ; dwCreationFlags
push 0x00 ; bInheritHandles
push 0x00 ; lpThreadAttributes
push 0x00 ; lpProcessAttributes
push esi ; lpCommandLine
push 0x00 ; lpApplicationName
call [edx + CreateProcessA]
mov edx, ebx ; replacing edx

; Call Exit Process
push 0x00
call [edx + Exit]




; returns module base in EAX
; EBP = Hash of desired module
get_module_address:

;walk PEB find target module
cld
xor edi, edi
mov edi, [FS:0x30]
mov edi, [edi+0xC]
mov edi, [edi+0x14]

next_module_loop:
mov esi, [edi+0x28]
xor edx, edx

module_hash_loop:
lodsw
test al, al
jz end_module_hash_loop
cmp al, 0x41
jb end_hash_check
cmp al, 0x5A
ja end_hash_check
or al, 0x20
end_hash_check:
rol edx, 7
xor dl, al
jmp module_hash_loop

end_module_hash_loop:

cmp edx, ebx
mov eax, [edi+0x10]
mov edi, [edi]
jnz next_module_loop

ret

get_api_address:
mov edx, ebp
add edx, [edx+3Ch]
mov edx, [edx+78h]
add edx, ebp
mov ebx, [edx+20h]
add ebx, ebp
xor ecx, ecx

load_api_hash:
push edi
push esi
mov esi, [esi]
; xor ecx, ecx

load_api_name:
mov edi, [ebx]
add edi, ebp
push edx
xor edx, edx

create_hash_loop:
rol edx, 7
xor dl, [edi]
inc edi
cmp byte [edi], 0
jnz create_hash_loop

xchg eax, edx
pop edx
cmp eax, esi
jz load_api_addy
add ebx, 4
inc ecx
cmp [edx+18h], ecx
jnz load_api_name
pop esi
pop edi
ret

load_api_addy:
pop esi
pop edi
lodsd
push esi
push ebx
mov ebx, ebp
mov esi, ebx
add ebx, [edx+24h]
lea eax, [ebx+ecx*2]
movzx eax, word [eax]
lea eax, [esi+eax*4]
add eax, [edx+1ch]
mov eax, [eax]
add eax, esi
stosd
pop ebx
pop esi
add ebx, 4
inc ecx
cmp dword [esi], 0FFFFh
jnz load_api_hash

ret

KERNEL32HASHTABLE:
	dd 0x46318ac7 ; CreateProcessA
	dd 0x95902b19 ; ExitProcess
	dd 0xc8ac8026 ; LoadLibraryA
	; dd 0xe8bf6dad  ; WinExec
	dd 0xFFFF ; make sure to end with this token

KERNEL32FUNCTIONSTABLE:
CreateProcessA:
	dd 0x00000000
ExitProcess:
	dd 0x00000001
LoadLibraryA:
	dd 0x00000002
; WinExec:
; 	dd 0x00000002

USER32HASHTABLE:
	dd 0xabbc680d ; messageboxa
	dd 0xFFFF

USER32FUNCTIONSTABLE:
MESSAGEBOXA:
	dd 0x00000003

USER32:
	db "user32.dll", 0

URLMONHASHTABLE:
	dd 0xd95d2399 ;  URLDownloadToFileA
	dd 0xFFFF

URLMONFUNCTIONSTABLE:
URLDOWNLOADTOFILE:
	dd 0x00000004

URLMON:
	db "urlmon.dll", 0

URL:
	db "http://images.freeimages.com/images/large-previews/199/sunflowers-6-1392951.jpg", 0

URLFILENAME:
	db "flower.jpeg", 0

EXE:
	db "mspaint.exe flower.jpeg"