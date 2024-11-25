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

payload = b""

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