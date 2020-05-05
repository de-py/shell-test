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

; call messageboxa
push 0x00 ; null byte for hi
push 0x6948 ; hi
mov eax, esp ; mov pointer to eax
push 0x00 ; push utype
push 0x00 ; push lpcaption
push eax ; push lptext
push 0x00 ; push hwnd
call [EDX + MESSAGEBOXA]


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
	dd 0x95902b19 ; ExitProcess
	dd 0xc8ac8026 ; LoadLibraryA
	; dd 0xe8bf6dad
	dd 0xFFFF ; make sure to end with this token

KERNEL32FUNCTIONSTABLE:
ExitProcess:
	dd 0x00000000
LoadLibraryA:
	dd 0x00000000

USER32HASHTABLE:
	dd 0xabbc680d ; messageboxa
	dd 0xFFFF

USER32FUNCTIONSTABLE:
MESSAGEBOXA:
	dd 0x00000001

USER32:
	db "user32.dll", 0
