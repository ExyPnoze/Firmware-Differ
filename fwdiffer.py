#!/usr/bin/env python3

__description__ = 'Firmware Comparison Tool with fuzzy hashing and ELF filtering'
__author__ = 'Léandre Guiset'
__version__ = '0.1.0'
__date__ = '2024/10/13'

"""
Source code put in the public domain by Léandre Guiset, no Copyrights
https://github.com/ExyPnoze
Use at your own risk.

History:
    version 0.0.1
    2024/10/04: start
    2024/10/05: add --show options
    version 0.1.0
    2024/10/07: Didier stevens python code template applied
                https://blog.didierstevens.com/my-python-templates/
    2024/10/07: add --manual options 
    2024/10/13: fuzzy hashing and ELF filtering added.
Todo:
    Option to choose md5 and more file types
    Error handling.
    Output result in a file.

Description:
    FWDiffer is a Python tool designed to compare two firmware versions by scanning their directories and identifying changes in files. 
    The tool recursively retrieves file paths, computes the MD5 hash for each file, applies fuzzy hashing, and filters ELF executable files. 
    It generates a report of three categories of changes:
      - Modified Files: Files that exist in both versions but have different content.
      - Added Files: Files that exist in the second version but not in the first.
      - Deleted Files: Files that exist in the first version but are missing in the second.
"""

import os
import hashlib
import argparse
from typing import Tuple, List

try:
    import ssdeep # For Fuzzy hashing
except ImportError:
    print('Module ssdeep missing, install: pip install ssdeep')
    exit(-1)

try:
    import magic  # For identifying ELF files
except ImportError:
    print('Module magic missing, intall: pip install magic')
    exit(-1)


def PrintManual():
    manual = r'''
Manual:

FWDiffer is a command-line tool for comparing firmware versions. It can identify modified, added, and deleted ELF files between two firmware directories.

Usage:
    python FWDiffer.py <firmware_a_path> <firmware_b_path> [--show modified|added|deleted] [--manual] [--threshold N]

Options:
    firmware_a_path    Path to the directory of firmware version A.
    firmware_b_path    Path to the directory of firmware version B.
    --show             Show only specified file categories: modified, added, or deleted.
    --manual           Display this manual.
    --threshold        Set similarity threshold for fuzzy hashing (default: 85).

Examples:
    python FWDiffer.py /path/to/firmwareA /path/to/firmwareB --show modified --threshold 90

The output will categorize files as:
  - Modified Files: Files in both versions but with different content.
  - Added Files: Files only in firmware B.
  - Deleted Files: Files only in firmware A.
'''
    print(manual)


def get_md5_footprint(file: str) -> str:
    """Returns the MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def get_fuzzy_hash(file: str) -> str:
    """Returns the fuzzy hash (ssdeep) of a file."""
    with open(file, "rb") as f:
        return ssdeep.hash(f.read())


def is_elf_file(file: str) -> bool:
    """Checks if a file is an ELF executable using python-magic."""
    file_type = magic.from_file(file, mime=True)
    return file_type == "application/x-executable"


def get_path(target: str) -> dict:
    """Recursively retrieves the paths of files in a directory."""
    paths = {}
    for root, dirs, files in os.walk(target):
        for file in files:
            full_path = os.path.join(root, file)
            if not os.path.islink(full_path):
                paths[file] = full_path
    return paths


def compare_versions(a: dict, b: dict, similarity_threshold: int) -> Tuple[List[str], List[str], List[str]]:
    """Compares two dictionaries of file paths and identifies modified, added, and deleted files."""
    modified_files = []
    added_files = []
    deleted_files = []

    for file in a.keys() & b.keys():
        if not is_elf_file(a[file]):
            continue

        fuzzy_a = get_fuzzy_hash(a[file])
        fuzzy_b = get_fuzzy_hash(b[file])

        similarity = ssdeep.compare(fuzzy_a, fuzzy_b)
        if similarity_threshold <= similarity < 100:
            modified_files.append(file)

    added_files = [file for file in b.keys() - a.keys() if is_elf_file(b[file])]
    deleted_files = [file for file in a.keys() - b.keys() if is_elf_file(a[file])]

    return modified_files, added_files, deleted_files


def print_tool_name():
    print("   █████ █     █░     ▓█████▄   ██▓ ▒ ████▒ ▒ ████▒ ▓█████ ██▀███  ")
    print(" ▓██    ▓█░ █ ░█░     ▒██▀ ██▌▒▓██▒▒▓██    ▒▓██     ▓█   ▀▓██ ▒ ██▒")
    print(" ▒████  ▒█░ █ ░█      ░██   █▌▒▒██▒░▒████  ░▒████   ▒███  ▓██ ░▄█ ▒")
    print(" ░▓█▒   ░█░ █ ░█     ▒░▓█▄   ▌░░██░░░▓█▒   ░░▓█▒    ▒▓█  ▄▒██▀▀█▄  ")
    print("▒░▒█░   ░░██▒██▓     ░░▒████▓ ░░██░ ░▒█░    ░▒█░   ▒░▒████░██▓ ▒██▒")
    print("░ ▒ ░   ░ ▓░▒ ▒      ░ ▒▒▓  ▒  ░▓    ▒ ░     ▒ ░   ░░░ ▒░ ░ ▒▓ ░▒▓░")
    print("░ ░       ▒ ░ ░        ░ ▒  ▒ ░ ▒ ░  ░       ░     ░ ░ ░    ░▒ ░ ▒ ")
    print("  ░ ░     ░   ░        ░ ░  ░ ░ ▒ ░  ░ ░     ░ ░       ░    ░░   ░ ")
    print("░           ░            ░      ░                  ░   ░     ░     ")


def print_modified(modified):
    print("Modified Files : \n")
    if modified:
        for file in modified:
            print(f"\033[35m - {file}\033[0m")
        print("\n")
    else:
        print('No executable modified. \n')


def print_added(added):
    print("Added Files : \n")
    if added:
        for file in added:
            print(f"\033[32m - {file}\033[0m")
        print("\n")
    else:
        print('No executable added. \n')


def print_deleted(deleted):
    print("Deleted Files : \n")
    if deleted:
        for file in deleted:
            print(f"\033[31m - {file}\033[0m")
        print("\n")
    else:
        print('No executable deleted. \n')


def main(firmware_a, firmware_b, show, threshold):
    a_paths = get_path(firmware_a)
    b_paths = get_path(firmware_b)

    modified, added, deleted = compare_versions(a_paths, b_paths, threshold)

    print_tool_name()

    if show == "modified":
        print_modified(modified)
    elif show == "added":
        print_added(added)
    elif show == "deleted":
        print_deleted(deleted)
    else:
        print_modified(modified)
        print_added(added)
        print_deleted(deleted)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tool to compare firmware versions.")
    parser.add_argument("--manual", action="store_true", help="Display the manual.")
    parser.add_argument("firmware_a", nargs="?", help="Firmware version A.")
    parser.add_argument("firmware_b", nargs="?", help="Firmware version B.")
    parser.add_argument("--show", choices=['modified', 'added', 'deleted'],
                        help="Display modified, added or deleted files.")
    parser.add_argument("--threshold", type=int, default=85,
                        help="Set similarity threshold for fuzzy hashing (default: 85).")

    args = parser.parse_args()

    if args.manual:
        PrintManual()
    elif args.firmware_a and args.firmware_b:
        main(args.firmware_a, args.firmware_b, args.show, args.threshold)
    else:
        parser.print_help()
