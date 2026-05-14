OPTION DOTNAME
OPTION CASEMAP:NONE

EXTERN g_OriginalNtAllocateVirtualMemory:QWORD
EXTERN BkntkiNtAllocateVirtualMemoryPreLog:PROC
EXTERN BkntkiHookEnter:PROC
EXTERN BkntkiHookExit:PROC

PUBLIC BkntkiNtAllocateVirtualMemoryHookStub

.code

BkntkiNtAllocateVirtualMemoryHookStub PROC
    mov r10, qword ptr [rsp+28h]
    mov r11, qword ptr [rsp+30h]

    sub rsp, 0D8h

    mov [rsp+80h], rax
    mov [rsp+88h], rcx
    mov [rsp+90h], rdx
    mov [rsp+98h], r8
    mov [rsp+0A0h], r9
    mov [rsp+0A8h], r10
    mov [rsp+0B0h], r11

    call BkntkiHookEnter

    mov rcx, [rsp+88h]
    mov rdx, [rsp+90h]
    mov r8, [rsp+98h]
    mov r9, [rsp+0A0h]
    mov r10, [rsp+0A8h]
    mov r11, [rsp+0B0h]
    mov [rsp+20h], r10
    mov [rsp+28h], r11
    call BkntkiNtAllocateVirtualMemoryPreLog

    mov rax, [rsp+80h]
    mov rcx, [rsp+88h]
    mov rdx, [rsp+90h]
    mov r8, [rsp+98h]
    mov r9, [rsp+0A0h]
    mov r10, [rsp+0A8h]
    mov r11, [rsp+0B0h]
    add rsp, 0D8h

    mov rax, r11
    mov r11, qword ptr [g_OriginalNtAllocateVirtualMemory]
    test r11, r11
    jnz short __bb_jump_to_original
    sub rsp, 28h
    call BkntkiHookExit
    add rsp, 28h
    mov eax, 0C0000001h
    ret

__bb_jump_to_original:
    sub rsp, 38h
    mov [rsp+20h], r10
    mov [rsp+28h], rax
    call r11
    mov [rsp+30h], rax
    call BkntkiHookExit
    mov rax, [rsp+30h]
    add rsp, 38h
    ret
BkntkiNtAllocateVirtualMemoryHookStub ENDP

END
