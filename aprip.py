#!/usr/bin/env python
#############################################################################
#
#                     _  _  _         _____   _                           
#       /\           | |(_)| |       |  __ \ (_)                          
#      /  \    _ __  | | _ | |__     | |__) | _  _ __   _ __    ___  _ __ 
#     / /\ \  | '_ \ | || || '_ \    |  _  / | || '_ \ | '_ \  / _ \| '__|
#   -/ ____ \ | |_) || || || |_) |  -| | \ \ | || |_) || |_) ||  __/| |   
# --/_/    \_\| .__/ |_||_||_.__/  --|_|  \_\|_|| .__/ | .__/  \___||_|   
#            -| |                              -| |   -| |                
#           --|_|                             --|_|  --|_|                   
#
#           [ We eat aplib compressed binaries for breakfast! ]
# 
# Use this library to automatically extract PE files compressed with aplib 
# from a binary blob. This is especially fun to run on memory dumps from 
# your sandbox... 
#
#############################################################################

__author__ = "@herrcore"
__version__ = "1.0"

import aplib 
import re
import argparse
import pefile

aplib_magic = (r"M8Z")
dos_strings = ["This program must be run under Win32", 
                "This program cannot be run in DOS mode", 
                "This program requires Win32", 
                "This program must be run under Win64"]


def find_candidates(blob):
    """Find potential aplib candidates.

    Args:
        blob (string): binary string of the blob to search

    Returns:
        list: offsets to each of the candidates (empty if none found)
    """
    out = []
    ire = re.finditer(aplib_magic, blob)
    for match in ire:
        out.append(match.start())
    return out


def extract_candidate(blob, offset):
    """Attempt to decrypt candidate and test DOS header

    Args:
        blob (string): binary string of the blob to search
        offset (int): offset in the blob (candidate start)

    Returns:
        string: extracted PE file (none if no PE is extracted)
    """
    # Attempt to decrypt DOS header and verify DOS string exists
    out = None
    try:
        candidate = blob[offset:]
        ptext = aplib.decompress(candidate).do()[0] 
        # Carve the first 128 bytes to check the DOS header
        flag_dos = False
        for egg in dos_strings:
            if egg in ptext[:128]:
                flag_dos = True

        # If this is a valid PE file find the length and trim it
        if flag_dos:
            pe = pefile.PE(data=ptext)
            # Remove overlay
            return pe.trim()
        else:
            # TODO: add in logging and option to pass this check
            return None
    except Exception as e:
        return None


def extract_all(blob):
    """Locate potential aplib candidates and attempt to decrypt them

    Args:
        blob (string): binary string of the blob to search

    Returns:
        list: list of PE files that have been extracted (empty if none are found)
    """

    # Locate all potential candidates 
    candidates = find_candidates(blob)

    # Extract valid candidates
    out = []
    for ptr in candidates:
        ptext = extract_candidate(blob, ptr)
        if ptext != None:
            out.append(ptext)
    return out



def main():
    parser = argparse.ArgumentParser(description="Find and extract aplib packed PE files. Output: dump1.bin, dump2.bin, ...")
    parser.add_argument("infile", help="File containing the binary blob to serach for aplib compressed binaries.")
    args = parser.parse_args()
    
    # Read data blob from file
    with open(args.infile, "rb") as fp:
        data = fp.read()

    # Extract all aplib compressed PE files
    pe_files = extract_all(data)

    # Write extracted PE files to dump1.bin, dump2.bin etc.
    for ptr in range(0,len(pe_files)):
        outfile = "dump%d.bin" % ptr
        with open(outfile, "wb") as fp:
            fp.write(pe_files[ptr])


if __name__ == '__main__':
    main()















