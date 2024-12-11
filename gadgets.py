import subprocess
import re
import sys
import os.path
import argparse
from sys import platform

# Coloring
RED, GREEN, BLUE, MAGENTA, RESET = "\033[31m", "\033[32m", "\033[34m", "\033[35m", "\033[0m"
ERR, GOOD = f"{RED}[!]{RESET}", f"{GREEN}[+]{RESET}"

"""
# file with cool gadgets
# gadgets for decoder
# find pushad; ret !!!
# push with more pops
# remove "push sth; ret;"
#todo make a filter for xchg
#todo look at https://github.com/0xbad53c/osed-tools/blob/main/filter-ropfile.py
# https://github.com/epi052/osed-scripts/blob/main/find-gadgets.py
#todo make an option for addresses to be relative with dll_base (add a new param for each lib that you grab gadgets from)
#todo make an option for changeing a maximum length of an gadget, fetched via rp++.exe
#todo integrate gadget finding with capstone engine
#todo enable ALL gadgets, not only ret;
"""

def clean_gadgets(lines):
    header_end = next((i for i, line in enumerate(lines) if "gadgets found." in line), -1)
    if header_end != -1:
        lines = lines[header_end + 1:]
    lines = [re.sub(r"\(\d+ found\)", "", line).strip() for line in lines]
    lines = [line.strip().replace('  ', ' ').replace('dword ', '').replace('ptr ', '').replace('byte ', '').replace(' ;', ';') for line in lines if line]
    return sorted(set(lines), key=len)

def fix_address_with_trailing_zeros(lines, args):
    clean_lines = []
    for line in lines:
        if args.base:
            base = line.split("+", 1)[0]
        address_part = line.split(":", 1)[0].lower().split('0x', 1)[1]
        gadget = line.split(":", 1)[1]
        
        if len(address_part) != 8:
            zeros = "0"*(8-len(address_part))
            if not args.base:
                line = "0x" + zeros + address_part + ":" + gadget
            else:
                line = base+ "+" +"0x" + zeros + address_part + ":" + gadget
        clean_lines.append(line)
    return clean_lines

def get_gadgets(file_path, args):
    if "linux" in platform:
        executable = './rp-lin'
    elif "win32" in platform:
        executable = 'rp++.exe'
    else:
        print("Sorry, bad system.")
        exit(1)
    if not args.base:
        cmd = f'{executable} -r 6 -f {file_path}'
    else:
        cmd = f'{executable} --va 0x0 -r 6 -f {file_path}'
    output = subprocess.run(cmd, shell=True, capture_output=True)
    if output.stderr:
        print(f"{ERR} stderr on rp++")
        print(f"{ERR} {output.stderr.decode()}")
    output_lines = output.stdout.decode().split('\n')
    
    clean_gadgets_list = clean_gadgets(output_lines)
    
    if args.base:
        basename = 'base_'+os.path.basename(file_path).split('.',1)[0]
        modified_array = [basename + '+' + item for item in clean_gadgets_list]
        clean_gadgets_list = modified_array
    
    clean_gadgets_list = fix_address_with_trailing_zeros(clean_gadgets_list, args)
    
    return clean_gadgets_list

def remove_gadgets_with_bad_bytes(gadgets, bad_bytes):
    bad_bytes_set = set(byte.lower() for byte in bad_bytes)
    filtered_gadgets = []
    for gadget in gadgets:
        address_part = gadget.split(":", 1)[0].lower()
        if any(address_part[i:i+2] in bad_bytes_set for i in range(0, len(address_part), 2)):
            continue  # Skip if a bad byte is found
        filtered_gadgets.append(gadget)
    
    return filtered_gadgets

def remove_non_ret_lines(gadgets):
    filtered_gadgets = [gadget for gadget in gadgets if gadget.endswith("ret;")]
    return filtered_gadgets

def remove_duplicates_after_colon(gadgets):
    seen = set()
    filtered_gadgets = []
    for gadget in gadgets:
        after_colon = gadget.split(":", 1)[1].strip()
        if after_colon not in seen:
            seen.add(after_colon)
            filtered_gadgets.append(gadget)
    return filtered_gadgets

def write_gadgets_to_file(args):
    all_gadgets = []
    for file in args.files:
        file_path = file
        gadgets = get_gadgets(file_path, args)
        bad_bytes_list = args.bad_chars
        gadgets = remove_gadgets_with_bad_bytes(gadgets, bad_bytes_list)
        if not args.all:
            gadgets = remove_non_ret_lines(gadgets)
        all_gadgets += gadgets
        
    all_gadgets = remove_duplicates_after_colon(all_gadgets)  
    print(f"{GOOD} Gadgets found: {len(all_gadgets)}")
    with open(args.output, "w") as file:
        for gadget in all_gadgets:
            file.write(f"{gadget}\n")

def find_gadget_with_regex(file, regex, max_results=1, filter=[], syntax=0):
    regex = re.compile(regex)
    matching_lines = []

    with open(file, 'r', encoding='UTF-8') as file:
        lines = [line.rstrip() for line in file]
        for gadget in lines:
            # search with regex and exclude filters
            if regex.search(gadget) and not any(f in gadget for f in filter):
                matching_lines.append(gadget)
                if len(matching_lines) >= max_results:
                    break
    
    # #todo implement various libraries bases
    res = []
    for m in matching_lines:
        if syntax == 0:
            res.append(m)
        elif syntax == 1:
            res.append('rop += pack("<L", ' + m.replace(":", ")\t#"))
        elif syntax == 2:
            res.append('rop += ' + m.replace(":", "\t#"))
    matching_lines = res
    
    return matching_lines

def find_cool_gadgets(args):
    print(f"{GOOD} Finding cool gadgets")

    registers = ['eax','ebx','ecx','edx','edi','esp','esi','ebp']
    print(f"{GOOD} pushad:")
    print(find_gadget_with_regex(args.output, r"pushad;", max_results=1, syntax=args.syntax)[0])
    print(f"{GOOD} POP:")
    for r in registers:
        for result in find_gadget_with_regex(args.output, fr"pop {r};", max_results=1, syntax=args.syntax):
            print(result)
    print(f"{GOOD} MOV:")
    for r in registers:
        # remove duplicates
        for result in list(set(find_gadget_with_regex(args.output, fr"mov {r}, ...;", max_results=len(registers)*2, syntax=args.syntax))):
            print(result)

def main(args):
    if args.files is not None and os.path.isfile(args.output) and not args.recreate:
        print(f"\n{GOOD} Using existing file: {args.output}\n")
    elif args.files is not None:
        print(f"{GOOD} Creating new gadgets file: {args.output}")
        write_gadgets_to_file(args)
        print(f"{GOOD} Gadgets saved to: {args.output}")

    if args.search is not None and not os.path.isfile(args.output):
        print("Please provide files to create file")
    elif args.cool:
        find_cool_gadgets(args)
    elif args.files is None and args.search is None:
        print("Use -h to print help")
    elif args.search is not None:
        for result in find_gadget_with_regex(args.output, args.search, max_results=args.count, syntax=args.syntax):
            print(result)
    
def cmdline_args():
    parser = argparse.ArgumentParser(
        description="""Searches for clean, categorized gadgets from a given list of files\n
        python3 gadgets.py -b 00 0a -f 'C:\\osed\\learning\\FastBackServer\\CSFTPAV6.DLL' -s all
        python3 gadgets.py -b 00 0a -s 'push eax; .* pop ebx'
        
        sudo python3 gadgets.py -f /home/kali/Desktop/Reverse/libspp.dll -b 00 0a 0d 25 26 2b 3d

        """
    )
    parser.add_argument(
        "-s",
        "--search",
        help="\"all\" - searches five the smallest usefull gadget. Else will perform regex on output file.",
        required=False,
        type=str,
    )
    parser.add_argument(
        "-c",
        "--count",
        help="count of regex returns",
        default=5,
        type=int
    )
    parser.add_argument(
        "-f",
        "--files",
        help="space separated list of files from which to pull gadgets. EVEN IF file is create this argument is used to specify bases",
        required=True,
        nargs="+",
    )
    parser.add_argument(
        "--syntax",
        help="0 - Raw, 1 - struct.pack, 2 - framework",
        default=0,
        type=int
    )
    parser.add_argument(
        "-b",
        "--bad-chars",
        help="space separated list of bad chars to omit from gadgets, e.g., 00 0a (default: empty)",
        default=[],
        nargs="+",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="name of output file where all (uncategorized) gadgets are written (default: gadgets.txt)",
        default="gadgets.txt",
    )
    parser.add_argument(
        "-a",
        "--all",
        help="get all gadgets. This includes: (ret+0x19; call esp+123) ... etc",
        default=False,
        action=argparse.BooleanOptionalAction
    )
    parser.add_argument(
        "--cool",
        help="Get auto filtered cool gadgets",
        default=False,
        action=argparse.BooleanOptionalAction
    )
    parser.add_argument(
        "--base",
        help="Uses default image offset",
        default=False,
        action=argparse.BooleanOptionalAction
    )
    parser.add_argument(
        "-r",
        "--recreate",
        help="Forces new output file creation",
        default=False,
        action=argparse.BooleanOptionalAction
    )
    return(parser.parse_args())

if __name__ == '__main__':
    main(cmdline_args())