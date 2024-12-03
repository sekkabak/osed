import sys

"""
Creates hash from function name to compare it later via assembly
"""

def ror_str(byte, count):
    binb = bin(byte)[2:].zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return (int(binb, 2))

if __name__ == '__main__':
    try:
        esi = sys.argv[1]   
    except IndexError:
        print("Usage: %s INPUTSTRING" % sys.argv[0])
        sys.exit()
    # Initialize variables
    edx = 0x00
    ror_count = 0
    for eax in esi:
        edx = edx + ord(eax)
        if ror_count < len(esi)-1:
            edx = ror_str(edx, 0xd)
        ror_count += 1
    print(hex(edx))