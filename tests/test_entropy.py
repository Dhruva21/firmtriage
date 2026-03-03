import os
import tempfile

from firmtriage.entropy import entropy

def test_empty_file_entropy():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
    
    try:
        result = entropy(tmp_path)

        assert result["entropy_shannon"] == 0.0
        assert result["bytes_analyzed"] == 0
        assert result["classification"] == "low"
    finally:
        os.remove(tmp_path)

def test_repeated_bytes_entropy():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"A" * 1024)  # repeated byte
        tmp_path = tmp.name

    try:
        result = entropy(tmp_path)

        assert result["entropy_shannon"] < 1.0
        assert result["classification"] == "low"

    finally:
        os.remove(tmp_path)

def test_random_bytes_entropy():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(os.urandom(4096))  # random bytes
        tmp_path = tmp.name

    try:
        result = entropy(tmp_path)

        assert result["entropy_shannon"] > 7.0
        assert result["classification"] == "high"

    finally:
        os.remove(tmp_path)