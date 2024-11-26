# todo

"FFD{0-7}" # call
"FFE{0-7}" # jmp
# FFD4    call esp
# FFD0    call eax
# FFD3    call ebx
# FFD1    call ecx
# FFD2    call edx
# FFE4    jmp esp
# FFE0    jmp eax
# FFE3    jmp ebx
# FFE1    jmp ecx
# FFE2    jmp edx
# s -b 00400000 00407000 FF E0