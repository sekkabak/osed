import sys
import struct

"""
Reimplementaion of msf-pattern_create and msf-pattern_offset in pure python
Credits: https://github.com/ickerwx/pattern
"""

def print_help():
    print('Usage: %s (create | offset) <value> <buflen>' % sys.argv[0])

def pattern_create(length = 8192):
    pattern = ''
    parts = ['A', 'a', '0']
    try:
        if not isinstance(length, int) and length.startswith('0x'):
            length = int(length, 16)
        elif not isinstance(length, int):
            length = int(length, 10)
    except ValueError:
        print_help()
        sys.exit(254)
    while len(pattern) != length:
        pattern += parts[len(pattern) % 3]
        if len(pattern) % 3 == 0:
            parts[2] = chr(ord(parts[2]) + 1)
            if parts[2] > '9':
                parts[2] = '0'
                parts[1] = chr(ord(parts[1]) + 1)
                if parts[1] > 'z':
                    parts[1] = 'a'
                    parts[0] = chr(ord(parts[0]) + 1)
                    if parts[0] > 'Z':
                        parts[0] = 'A'
    return pattern

def pattern_offset(value, length = 8192):
    try:
        if isinstance(value, str):
            if not value.startswith('0x'):
                value = '0x'+value
            value = struct.pack("<L", (int(value, 0)))
    except ValueError:
        print_help()
        sys.exit(1)
    pattern = pattern_create(length)
    try:
        return pattern.index(value.decode())
    except ValueError:
        return 'Not found'

def main():
    if len(sys.argv) < 3 or sys.argv[1].lower() not in ['create', 'offset']:
        print_help()
        sys.exit(0)

    command = sys.argv[1].lower()
    num_value = sys.argv[2]

    if command == 'create':
        print(pattern_create(num_value))
    elif command == 'offset':
        if len(sys.argv) == 3:
            print(pattern_offset(num_value))  
        else:
            print(pattern_offset(num_value, sys.argv[3]))  

if __name__ == '__main__':
    main()