"""
Purpose: 
    Detect common file signatures (magic bytes) inside firmware blobs.

Input:
    data: bytes

Output:
    dict
"""
from typing import Dict, List

MAGIC_SIGNATURES = {
    b"\x7fELF": "ELF Executable",
    b"MZ": "PE Executable",
    b"\x50\x4b\x03\x04": "ZIP Archive",
    b"\x1f\x8b": "GZIP Archive",
    b"\xfd7zXZ\x00": "XZ Archive",
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"\xff\xd8\xff": "JPEG Image",
    b"hsqs": "SquashFS",
    b"UBI#": "UBIFS",
}

def scan_magic(data: bytes):
    """
    Scan raw bytes for known magic signatures

    Returns:
        {
            "count_total": int,
            "matches": list[str]
        }
    """
    matches = []

    for signature, file_type in MAGIC_SIGNATURES.items():
        if signature in data:
            matches.append(file_type)
        
    return {
        "count_total": len(matches),
        "matches": matches
    }