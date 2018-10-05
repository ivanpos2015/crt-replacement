	BITS 64

	push rbp
	mov rbp, rsp  
	mov r9, rcx
	xor rcx, rcx
	mov rdx, 1
	xor r8, r8
	sub rsp, 32
	call r9
	add rsp, 32
	pop rbp
	ret