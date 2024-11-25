from keystone import *

def make_asm():
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    CODE = (input())
    encoding, count = ks.asm(CODE)
    instructions = ""
    python_hex = ""
    for dec in encoding:
        instructions += "{0:02X}".format(int(dec)).rstrip("\n") 
        python_hex += "\\x{0:02X}".format(int(dec)).rstrip("\n") 
    print('\n'+ python_hex +"    "+instructions + '    ' + CODE +'\n')

try:
    while True:
        try:
            make_asm()
        except KsError as e:
            print(e)
except (KeyboardInterrupt, EOFError):
    pass