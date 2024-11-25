import subprocess
import re
import sys
import os.path
import argparse

def clean_gadgets(lines):
    header_end = next((i for i, line in enumerate(lines) if "gadgets found." in line), -1)
    if header_end != -1:
        lines = lines[header_end + 1:]
    lines = [re.sub(r"\(\d+ found\)", "", line).strip() for line in lines]
    lines = [line.strip().replace('  ', ' ').replace('dword ', '').replace('ptr ', '').replace(' ;', ';') for line in lines if line]
    return sorted(set(lines), key=len)

def get_gadgets(file_path):
    cmd = f'C:\\osed\\rp++.exe -r 6 -f {file_path}'
    output = subprocess.run(cmd, shell=True, capture_output=True)
    output_lines = output.stdout.decode().split('\n')
    clean_gadgets_list = clean_gadgets(output_lines)
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

def print_useful_regex(output):
    reg_prefix = "e"
    len_sort = "| awk '{ print length, $0 }' | sort -n -s -r | cut -d' ' -f2- | tail"
    any_reg = f'{reg_prefix}..'

    search_terms = list()
    search_terms.append(f'(jmp|call) {reg_prefix}sp;')
    search_terms.append(fr'mov {any_reg}, \[{any_reg}\];')
    search_terms.append(fr'mov \[{any_reg}\], {any_reg};')
    search_terms.append(fr'mov {any_reg}, {any_reg};')
    search_terms.append(fr'xchg {any_reg}, {any_reg};')
    search_terms.append(fr'push {any_reg};.*pop {any_reg};')
    search_terms.append(fr'inc {any_reg};')
    search_terms.append(fr'dec {any_reg};')
    search_terms.append(fr'neg {any_reg};')
    search_terms.append(fr'push {any_reg};')
    search_terms.append(fr'pop {any_reg};')
    search_terms.append('pushad;')
    search_terms.append(fr'and {any_reg}, ({any_reg}|0x.+?);')
    search_terms.append(fr'xor {any_reg}, ({any_reg}|0x.+?);')
    search_terms.append(fr'add {any_reg}, ({any_reg}|0x.+?);')
    search_terms.append(fr'sub {any_reg}, ({any_reg}|0x.+?);')
    search_terms.append(fr'(lea|mov|and) \[?{any_reg}\]?, 0;')

    print(f"[+] helpful regex for searching within {output}\n")

    for term in search_terms:
        print(f"egrep '{term}' {output} {len_sort}")

def write_gadgets_to_file(args):
    all_gadgets = []
    for file in args.files:
        file_path = file
        gadgets = get_gadgets(file_path)
        bad_bytes_list = args.bad_chars
        gadgets = remove_gadgets_with_bad_bytes(gadgets, bad_bytes_list)
        gadgets = remove_non_ret_lines(gadgets)
        all_gadgets += gadgets
        
    all_gadgets = remove_duplicates_after_colon(all_gadgets)  
    with open(args.output, "w") as file:
        for gadget in all_gadgets:
            file.write(f"{gadget}\n")

def find_gadget_with_regex(file, regex, max_results=1, filter=[], to_python=True):
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
    if to_python:
        output = []
        for m in matching_lines:
            output.append('rop += pack("<L", ' + m.replace(":", ")\t#"))
        matching_lines = output
    return matching_lines

def find_cool_gadgets(args):
    print("Finding cool gadgets")

    print("Load from memory to register: mov e.., \\[e..\\];")
    for result in find_gadget_with_regex(args.output, r"mov e.., (dword\s+)?\[e..\];", max_results=5, filter=['eax, [eax]', 'ebx, [ebx]', 'ecx, [ecx]', 'esp, [esp]', 'esi, [esi]']):
        print(result)

    print("Load from memory to register: lea e.., \\[e..\\];")
    for result in find_gadget_with_regex(args.output, r"mov e.., (dword\s+)?\[e..\];", max_results=5, filter=['eax, [eax]', 'ebx, [ebx]', 'ecx, [ecx]', 'esp, [esp]', 'esi, [esi]']):
        print(result)

    print("Save register to memory: mov \\[e..\\], e..;")
    for result in find_gadget_with_regex(args.output, r"mov \[e..\], e..;", max_results=args.count, filter=['[eax], eax', '[ebx], ebx', '[ecx], ecx', '[esp], esp', '[esi], esi']):
        print(result)

    print("Save ESP: mov e.., esp;")
    for result in find_gadget_with_regex(args.output, r"mov e.., esp;", max_results=args.count):
        print(result)

    print("Push ESP, then pop: push esp; pop e..;")
    for result in find_gadget_with_regex(args.output, r"push esp;.* pop e..;", max_results=args.count):
        print(result)

    print("sub e.., e..;")
    for result in find_gadget_with_regex(args.output, r"sub e.., e..;", max_results=args.count):
        print(result)

    print("add e.., e..;")
    for result in find_gadget_with_regex(args.output, r"add e.., e..;", max_results=args.count):
        print(result)

    print("dec e.., e..;")
    for result in find_gadget_with_regex(args.output, r"dec e..;", max_results=args.count):
        print(result)
    
    print("inc e.., e..;")
    for result in find_gadget_with_regex(args.output, r"inc e..;", max_results=args.count):
        print(result)


def main(args):
    if args.files is not None:
        write_gadgets_to_file(args)
        print(f"Gadgets saved to: {args.output}")

    if args.search is not None and not os.path.isfile(args.output):
        print("Please provide files to create file")
    elif args.search == "all":
        find_cool_gadgets(args)
    elif args.files is None and args.search is None:
        print("Please provide valid args")
    elif args.search is not None:
         for result in find_gadget_with_regex(args.output, args.search, max_results=args.count, to_python=(not args.no_python)):
            print(result)
    
def cmdline_args():
    parser = argparse.ArgumentParser(
        description="""Searches for clean, categorized gadgets from a given list of files\n
        python3 gadgets.py -b 00 0a -f 'C:\\osed\\learning\\FastBackServer\\CSFTPAV6.DLL' -s all
        python3 gadgets.py -b 00 0a -s 'push eax; .* pop ebx'
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
        help="space separated list of files from which to pull gadgets",
        required=False,
        nargs="+",
    )
    parser.add_argument(
        "--no_python",
        help="Turn offs python sentax for grep",
        default=False,
        action=argparse.BooleanOptionalAction
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
    return(parser.parse_args())

if __name__ == '__main__':
    if sys.version_info<(3,5,0):
        sys.stderr.write("You need python 3.5 or later to run this script\n")
        sys.exit(1)
    main(cmdline_args())