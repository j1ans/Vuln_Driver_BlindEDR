.CODE

Syscall_NtDrawText PROC
    xor rax,rax
    mov rax,rdx
    mov rdx,rcx

    
    syscall
    ret
    

Syscall_NtDrawText ENDP


END