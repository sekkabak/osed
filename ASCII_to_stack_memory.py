import sys

def ascii_to_push_instructions(ascii_str):
    # Convert ASCII string to bytes
    byte_values = ascii_str.encode('ascii')
    # Split bytes into 4-byte chunks
    chunks = [byte_values[i:i+4] for i in range(0, len(byte_values), 4)]
    # Reverse the chunks and prepare push instructions
    push_instructions = []
    for chunk in chunks:
        # Fill the chunk with 0s if it has less than 4 bytes
        chunk = chunk.ljust(4, b'\x00')
        # Reverse the byte order and convert to hex
        reversed_chunk = int.from_bytes(chunk, byteorder='little')
        push_instructions.append(f"push 0x{reversed_chunk:08x}")
    # Reverse and print the push instructions
    push_instructions.reverse()
    for instruction in push_instructions:
        print(instruction)

if __name__ == '__main__':
    try:
        ascii = sys.argv[1]
        ascii_to_push_instructions(ascii)
    except IndexError:
        print("Usage: %s INPUTSTRING" % sys.argv[0])
        sys.exit()