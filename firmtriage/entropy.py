'''
entropy.py

Purpose:
	•	Shannon entropy - 
	•	Risk classification

Input:
	•	raw bytes

Output:
	•	dict

Entropy - Shannon entropy
	- in this context it about measuring how random the byte distribution of a file (or section) is.

Entropy is used to detect:
- encrypted blobs
- compressed sections
- packed malware
- embedded keys
- random data regions
- obfuscated payloads

High entropy = looks random
Low entropy = structured / ASCII / code / config
'''
import os
import math
from collections import Counter

# v1 - whole file is fine
def _read_bytes(filepath: str) -> bytes:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"{filepath} does not exist or is not a file")
    with open(filepath, "rb") as f:
        return f.read()

#shannon entropy function for bytes -> returns 0.8
def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data) # counts each byte value 0..255
    n = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy

def classify_entropy(h):
    if h >= 7.5:
        return "high"	# likely compressed/enc/packed
    if h >= 5.5:	
        return "medium"	# mixed/structured
    return "low"		# plaintext/structured/repetitive

def entropy(filepath):
    data = _read_bytes(filepath)
    h = shannon_entropy(data)
    return {
        "entropy_shannon": round(h, 4),
        "bytes_analyzed": len(data),
        "classification": classify_entropy(h),
	}