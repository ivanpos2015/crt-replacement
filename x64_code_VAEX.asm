BITS 64

;mov r10, rcx ;mov r10, 0x00000000000000D4
mov eax, dword [rsp]
mov dword [rsp + 48], eax
mov rcx, qword [rsp + 4h] ;process handle
mov rdx, qword [rsp + 0Ch] ;base address
mov r8, 0 ;zero bits
mov r9, qword [rsp + 14h] ;region size
sub rsp, 8
mov r10, rcx
mov eax, 0x0A0A0A0A;syscall index will get written here
syscall
mov rdx, rax
add rsp, 8
add rsp, 48
mov rcx, rsp
mov rax, 2Bh
push rax
push rcx
mov rax, 246h
push rax
mov rax, 23h
push rax
mov rax, 0h
push rax
mov rax, rdx
iretq