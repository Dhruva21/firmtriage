'''
Purpose:
	•	File size
	•	Hash calculation
	•	Maybe file type later

Input:
	•	filepath

Output:
	•	dict
'''
import os
import hashlib
import mimetypes

def metadata(filepath): 
    result = {
        "size": None,
        "hash": None,
        "type": None
    }

    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"{filepath} does not exist or is not a file")
    
    # file size
    result["size"] = os.path.getsize(filepath)

    #SHA256 hash calc
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    result["hash"] = sha256.hexdigest()

    # File type (MIME guess based on extension)
    file_type, _ = mimetypes.guess_type(filepath)
    result["type"] = file_type if file_type else "unknown"

    return result