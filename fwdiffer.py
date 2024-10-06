#!/usr/bin/env python3

"""
Source code put in the public domain by Léandre Guiset, no Copyright
https://github.com/ExyPnoze
Use at your own risk

History:
    2024/10/04: start
    2024/10/05: add --show options
Todo:
    Full path not only the file name.
    output in a file.
    
Firmware Comparison Tool

FWDiffer is a Python tool designed to compare two firmware versions by 
scanning their directories and identifying changes in files. The tool 
recursively retrieves file paths, computes the MD5 hash for each file, 
and compares the hashes between two versions. It generates a report of 
three categories of changes:
  - Modified Files: Files that exist in both versions but have different content.
  - Added Files: Files that exist in the second version but not in the first.
  - Deleted Files: Files that exist in the first version but are missing in the second.

This tool can be useful for firmware developers, reverse engineers, or 
anyone needing to track changes between different firmware builds.

"""

import os
import hashlib
from typing import Tuple, List
import argparse


def get_md5_footprint(file: str) -> str:
    """
    The function return the md5 hash of a file.
    :param file: file to hash.
    :rtype: str.
    :return: The md5 footprint of a specified file.
    """
    hash_md5 = hashlib.md5()

    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)

    return hash_md5.hexdigest()


def get_path(target: str) -> dict:
    """
    The function retrieves the paths of files in a directory recursively.
    :param target: Firmware directory.
    :rtype: dict.
    :return: File paths in a directory.
    """
    paths = {}

    for root, dirs, files in os.walk(target):
        for file in files:
            full_path = os.path.join(root, file)
            # ignore symbolic linkq
            if not os.path.islink(full_path):
                paths[file] = full_path

    return paths


def compare_versions(a: dict, b: dict) -> Tuple[List[str], List[str], List[str]]:
    """
    Compare two dictionaries of file paths and identify modified, added, and deleted files.
    :param a: Dictionary with file names as keys and their paths from version A.
    :param b: Dictionary with file names as keys and their paths from version B.
    :rtype: Tuple[List[str], List[str], List[str]]
    :return: A tuple containing three lists:
             - modified_files: Files that have been modified.
             - added_files: Files that are present in version B but not in version A.
             - deleted_files: Files that are present in version A but not in version B.
    """
    modified_files = []  # a != b
    added_files = []  # vb - va
    deleted_files = []  # va - vb

    for file in a.keys() & b.keys():
        hash_a = get_md5_footprint(a[file])
        hash_b = get_md5_footprint(b[file])

        if hash_a != hash_b:
            modified_files.append(file)

    added_files = list(b.keys() - a.keys())
    deleted_files = list(a.keys() - b.keys())

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
    for file in modified:
        print(f"\033[35m - {file}\033[0m") # Purple


def print_added(added):
    print("Added Files : \n")
    for file in added:
        print(f"\033[32m - {file}\033[0m")  # Green


def print_deleted(deleted):
    print("Deleted Files : \n")
    for file in deleted:
        print(f"\033[31m - {file}\033[0m")  # Red


def main(firmware_a, firmware_b, show):
    a_paths = get_path(firmware_a)
    b_paths = get_path(firmware_b)

    modified, added, deleted = compare_versions(a_paths, b_paths)

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
    parser.add_argument("firmware_a", help="Firmware version A.")
    parser.add_argument("firmware_b", help="Firmware version B.")
    parser.add_argument("--show", choices=['modified','added','deleted'],
                        help="Display modified, added or deleted files.")

    args = parser.parse_args()

    main(args.firmware_a, args.firmware_b, args.show)

