import os
import tempfile
import hashlib
from firmtriage.metadata import metadata

def test_metadata_basic():
    # create temp file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"hello world")
        tmp_path = tmp.name
    
    try:
        result = metadata(tmp_path)

        # check size
        assert result["size"] == 11

        # check hash
        expected_hash = hashlib.sha256(b"hello world").hexdigest()
        assert result["hash"] == expected_hash

        #type might be unknown since no extension
        assert result["type"] in ("unknown", None)
    finally:
        os.remove(tmp_path)
    